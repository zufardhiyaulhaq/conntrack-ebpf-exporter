# Direction Labels + Node IP Detection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add bidirectional attribution (direction=source and direction=destination labels) to both kernel conntrack and Cilium CT metrics, and detect the node's own IP as a known entity.

**Architecture:** Each connection produces two metric entries — one for the source IP (direction=source) and one for the destination IP (direction=destination). The kernel conntrack BPF program switches from netns-inode-based keys to IP-based keys with a direction field. The Cilium reader emits two count keys per CT entry. The resolver gains a SetNodeInfo method to register the node IP. The DaemonSet passes NODE_IP via Kubernetes Downward API.

**Tech Stack:** eBPF/C (kprobes), Go (cilium/ebpf, prometheus/client_golang, client-go), Kubernetes Downward API

---

### Task 1: Update Go types for direction-aware MapKey

**Files:**
- Modify: `pkg/ebpf/types.go`

**Step 1: Update types.go with direction constants and IP-based MapKey**

Replace the entire content of `pkg/ebpf/types.go` with:

```go
package ebpf

// Protocol bucket constants — must match BPF C defines in conntrack.c.
const (
	ProtoTCP   uint8 = 0
	ProtoUDP   uint8 = 1
	ProtoOther uint8 = 2
)

// ProtoNames maps protocol bucket constants to Prometheus label values.
var ProtoNames = map[uint8]string{
	ProtoTCP:   "tcp",
	ProtoUDP:   "udp",
	ProtoOther: "other",
}

// Direction constants — must match BPF C defines in conntrack.c.
const (
	DirectionSource uint8 = 0
	DirectionDest   uint8 = 1
)

// DirectionNames maps direction constants to Prometheus label values.
var DirectionNames = map[uint8]string{
	DirectionSource: "source",
	DirectionDest:   "destination",
}

// MapKey matches the BPF map key struct in conntrack.c.
type MapKey struct {
	IP        uint32
	Proto     uint8
	Direction uint8
	Pad       [2]uint8
}

// MapReader reads counters from the BPF map.
type MapReader interface {
	ReadCounters() (map[MapKey]int64, error)
	Close() error
}
```

**Step 2: Verify the types compile**

Run: `go vet ./pkg/ebpf/...`
Expected: Compilation errors in collector.go and collector_test.go (they reference `NetnsInode` which no longer exists). This is expected — we'll fix those in later tasks.

---

### Task 2: Update BPF C program for IP-based keys with direction

**Files:**
- Modify: `bpf/conntrack.c`

**Step 1: Update conntrack.c with IP-based map_key and direction**

Replace the entire content of `bpf/conntrack.c` with:

```c
//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/* BPF_ANY is a #define, not in kernel BTF / vmlinux.h */
#define BPF_ANY 0

// Protocol buckets — must match Go constants in types.go
#define PROTO_TCP   0
#define PROTO_UDP   1
#define PROTO_OTHER 2

// Direction — must match Go constants in types.go
#define DIR_SOURCE 0
#define DIR_DEST   1

struct map_key {
    __u32 ip;         /* IPv4 address in network byte order */
    __u8  proto;      /* 0=tcp, 1=udp, 2=other */
    __u8  direction;  /* 0=source, 1=destination */
    __u8  pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct map_key);
    __type(value, __s64);
} conntrack_counts SEC(".maps");

static __always_inline __u8 get_proto_bucket(struct nf_conn *ct) {
    __u8 protonum;
    protonum = BPF_CORE_READ(ct, tuplehash[0].tuple.dst.protonum);

    if (protonum == IPPROTO_TCP) {
        return PROTO_TCP;
    }

    if (protonum == IPPROTO_UDP) {
        return PROTO_UDP;
    }

    return PROTO_OTHER;
}

static __always_inline void update_count(struct map_key *key, __s64 delta) {
    __s64 *val = bpf_map_lookup_elem(&conntrack_counts, key);
    if (val) {
        __s64 new_val = __sync_fetch_and_add(val, delta) + delta;
        if (delta < 0 && new_val <= 0) {
            bpf_map_delete_elem(&conntrack_counts, key);
        }
    } else if (delta > 0) {
        __s64 initval = delta;
        bpf_map_update_elem(&conntrack_counts, key, &initval, BPF_ANY);
    }
}

// Note: The decrement and delete are non-atomic. A concurrent count_insert on
// another CPU could increment between the two operations, and the subsequent
// delete would lose that insert. This is an accepted tradeoff — the goal is
// finding offending pods (100K+ entries), not exact per-entry accounting.
// Stale zero entries are harmless (userspace skips count <= 0).
static __always_inline void count_entries(struct nf_conn *ct, __s64 delta) {
    __u8 proto = get_proto_bucket(ct);
    __u32 src_ip = BPF_CORE_READ(ct, tuplehash[0].tuple.src.u3.ip);
    __u32 dst_ip = BPF_CORE_READ(ct, tuplehash[0].tuple.dst.u3.ip);

    struct map_key src_key = {};
    src_key.ip = src_ip;
    src_key.proto = proto;
    src_key.direction = DIR_SOURCE;

    struct map_key dst_key = {};
    dst_key.ip = dst_ip;
    dst_key.proto = proto;
    dst_key.direction = DIR_DEST;

    update_count(&src_key, delta);
    update_count(&dst_key, delta);
}

SEC("kprobe/nf_conntrack_hash_check_insert")
int BPF_KPROBE(kprobe_ct_insert, struct nf_conn *ct) {
    count_entries(ct, 1);
    return 0;
}

SEC("kprobe/nf_ct_delete")
int BPF_KPROBE(kprobe_ct_delete, struct nf_conn *ct) {
    count_entries(ct, -1);
    return 0;
}
```

**Step 2: Verify the C file has no syntax issues**

Visual inspection only — compilation requires the BPF toolchain which runs on-node.

---

### Task 3: Update loader.go ReadCounters comment

**Files:**
- Modify: `pkg/ebpf/loader.go`

**Step 1: Update the ReadCounters comment**

Change line 118 in `pkg/ebpf/loader.go`:

```go
// Before:
// ReadCounters iterates the BPF hash map and returns all {netns_inode, proto} → count pairs.

// After:
// ReadCounters iterates the BPF hash map and returns all {ip, proto, direction} → count pairs.
```

**Step 2: Verify loader compiles**

Run: `go vet ./pkg/ebpf/...`
Expected: Should compile (loader.go uses `MapKey` as an opaque struct from the map iterator).

---

### Task 4: Update CiliumCountKey with Direction field

**Files:**
- Modify: `pkg/ebpf/cilium_types.go`

**Step 1: Update CiliumCountKey**

Replace the entire content of `pkg/ebpf/cilium_types.go` with:

```go
package ebpf

// CiliumCountKey aggregates Cilium conntrack entries by IP, protocol, and direction.
type CiliumCountKey struct {
	IP        string // source or destination IP
	Protocol  string // "tcp", "udp", "other"
	Direction string // "source" or "destination"
}

// CiliumReader reads conntrack entry counts from Cilium's BPF CT maps.
type CiliumReader interface {
	ReadCounts() (map[CiliumCountKey]int64, error)
	Close() error
}
```

**Step 2: Verify types compile**

Run: `go vet ./pkg/ebpf/...`
Expected: Compilation errors in cilium.go and cilium_collector_test.go (they reference `SourceIP`). Expected — fixed in next tasks.

---

### Task 5: Update Cilium reader to emit two entries per connection

**Files:**
- Modify: `pkg/ebpf/cilium.go`

**Step 1: Update iterateMap to emit source + destination count keys**

In `pkg/ebpf/cilium.go`, replace the `iterateMap` function (lines 94-132) with:

```go
func (r *CiliumMapReader) iterateMap(m *ebpf.Map, result map[CiliumCountKey]int64) error {
	var tuple ciliumCT4Tuple
	var value [56]byte // CT entry value — we don't parse it, just need the key

	iter := m.Iterate()
	for iter.Next(&tuple, &value) {
		// Only count original-direction entries (Flags bit 0 == 0).
		// Cilium stores two entries per connection (original + reply).
		// Counting both would double the metrics.
		if tuple.Flags&0x1 != 0 {
			continue
		}

		sourceIP := net.IPv4(tuple.SourceAddr[0], tuple.SourceAddr[1], tuple.SourceAddr[2], tuple.SourceAddr[3])
		destIP := net.IPv4(tuple.DestAddr[0], tuple.DestAddr[1], tuple.DestAddr[2], tuple.DestAddr[3])

		var proto string
		switch tuple.NextHdr {
		case 6:
			proto = "tcp"
		case 17:
			proto = "udp"
		default:
			proto = "other"
		}

		srcKey := CiliumCountKey{IP: sourceIP.String(), Protocol: proto, Direction: "source"}
		dstKey := CiliumCountKey{IP: destIP.String(), Protocol: proto, Direction: "destination"}
		result[srcKey]++
		result[dstKey]++
	}

	if err := iter.Err(); err != nil {
		if errors.Is(err, ebpf.ErrIterationAborted) {
			log.Warn("Cilium CT map iteration aborted, partial results returned")
			return nil
		}
		return err
	}

	return nil
}
```

Also update the ReadCounts godoc comment (line 76-78):

```go
// ReadCounts iterates Cilium's CT maps and returns entry counts grouped by
// IP, protocol, and direction. Each original-direction CT entry produces two
// count keys: one for the source IP and one for the destination IP.
```

**Step 2: Verify cilium.go compiles**

Run: `go vet ./pkg/ebpf/...`
Expected: Pass (all references to `SourceIP` in cilium.go are now removed).

---

### Task 6: Add SetNodeInfo to resolver

**Files:**
- Modify: `pkg/resolver/resolver.go`
- Modify: `pkg/resolver/resolver_test.go`

**Step 1: Add SetNodeInfo method to PodResolver**

Add this method after the `RemovePod` method (after line 278) in `pkg/resolver/resolver.go`:

```go
// SetNodeInfo registers the node's IP so traffic from/to the node itself
// is attributed as pod="node", namespace="kube-system", app=<nodeName>.
func (r *PodResolver) SetNodeInfo(nodeIP, nodeName string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ipCache[nodeIP] = PodInfo{Name: "node", Namespace: "kube-system", App: nodeName}
}
```

**Step 2: Add test for SetNodeInfo**

Add this test at the end of `pkg/resolver/resolver_test.go`:

```go
func TestSetNodeInfo(t *testing.T) {
	r := &PodResolver{
		cache:     make(map[uint32]PodInfo),
		ipCache:   make(map[string]PodInfo),
		podInodes: make(map[string][]uint32),
		podIPs:    make(map[string][]string),
		mu:        sync.RWMutex{},
	}

	r.SetNodeInfo("192.168.1.10", "node-abc")

	info, ok := r.ResolveByIP("192.168.1.10")
	if !ok {
		t.Fatal("expected node IP to resolve")
	}
	if info.Name != "node" {
		t.Errorf("expected name 'node', got %s", info.Name)
	}
	if info.Namespace != "kube-system" {
		t.Errorf("expected namespace 'kube-system', got %s", info.Namespace)
	}
	if info.App != "node-abc" {
		t.Errorf("expected app 'node-abc', got %s", info.App)
	}
}
```

**Step 3: Run resolver tests**

Run: `go test ./pkg/resolver/ -v`
Expected: 8/8 pass (7 existing + 1 new).

---

### Task 7: Update kernel conntrack collector with direction label

**Files:**
- Modify: `pkg/metrics/collector.go`
- Modify: `pkg/metrics/collector_test.go`

**Step 1: Update collector.go for IP-based resolution and direction label**

Replace the entire content of `pkg/metrics/collector.go` with:

```go
package metrics

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"
)

const (
	metricName = "node_conntrack_ebpf_entries_by_pod"
	metricHelp = "Number of conntrack entries per pod, broken down by protocol and direction."
)

var desc = prometheus.NewDesc(
	metricName,
	metricHelp,
	[]string{"pod", "namespace", "app", "protocol", "direction"},
	nil,
)

type conntrackMetricKey struct {
	pod, namespace, app, protocol, direction string
}

// Collector implements prometheus.Collector for per-pod conntrack metrics.
type Collector struct {
	reader   ebpfpkg.MapReader
	resolver resolver.Resolver
}

// NewCollector creates a new Collector.
func NewCollector(reader ebpfpkg.MapReader, resolver resolver.Resolver) *Collector {
	return &Collector{reader: reader, resolver: resolver}
}

// Describe sends the metric descriptor.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- desc
}

// Collect reads BPF counters, resolves pods by IP, aggregates by label set, and emits metrics.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	counters, err := c.reader.ReadCounters()
	if err != nil {
		log.Errorf("Failed to read BPF counters: %v", err)
		ch <- prometheus.NewInvalidMetric(desc, err)
		return
	}

	aggregated := make(map[conntrackMetricKey]float64)

	for key, count := range counters {
		if count <= 0 {
			continue
		}

		ip := uint32ToIP(key.IP)

		podName := "unknown"
		namespace := "unknown"
		app := "unknown"

		info, ok := c.resolver.ResolveByIP(ip)
		if ok {
			podName = info.Name
			namespace = info.Namespace
			app = info.App
		}

		protoName, ok := ebpfpkg.ProtoNames[key.Proto]
		if !ok {
			protoName = "other"
		}

		dirName, ok := ebpfpkg.DirectionNames[key.Direction]
		if !ok {
			dirName = "source"
		}

		mk := conntrackMetricKey{
			pod:       podName,
			namespace: namespace,
			app:       app,
			protocol:  protoName,
			direction: dirName,
		}
		aggregated[mk] += float64(count)
	}

	for mk, total := range aggregated {
		metric, err := prometheus.NewConstMetric(
			desc,
			prometheus.GaugeValue,
			total,
			mk.pod, mk.namespace, mk.app, mk.protocol, mk.direction,
		)
		if err != nil {
			log.Errorf("Failed to create metric: %v", err)
			continue
		}
		ch <- metric
	}
}

// uint32ToIP converts a uint32 in network byte order to a dotted-decimal IP string.
func uint32ToIP(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
```

Note: We import `"encoding/binary"`, `"fmt"`, and `"net"` (net may be unused — remove if go vet complains). The `uint32ToIP` function converts the BPF map key's IP (stored in network byte order) to a string for resolver lookup.

**Step 2: Update collector_test.go for IP-based keys and direction**

Replace the entire content of `pkg/metrics/collector_test.go` with:

```go
package metrics

import (
	"encoding/binary"
	"net"
	"testing"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"

	"github.com/prometheus/client_golang/prometheus"
)

type mockMapReader struct {
	counters map[ebpfpkg.MapKey]int64
	err      error
}

func (m *mockMapReader) ReadCounters() (map[ebpfpkg.MapKey]int64, error) {
	return m.counters, m.err
}

func (m *mockMapReader) Close() error { return nil }

type mockResolver struct {
	pods map[uint32]resolver.PodInfo
	ips  map[string]resolver.PodInfo
}

func (m *mockResolver) Resolve(netnsInode uint32) (resolver.PodInfo, bool) {
	info, ok := m.pods[netnsInode]
	return info, ok
}

func (m *mockResolver) ResolveByIP(ip string) (resolver.PodInfo, bool) {
	if m.ips == nil {
		return resolver.PodInfo{}, false
	}
	info, ok := m.ips[ip]
	return info, ok
}

// ipToUint32 converts an IP string to a uint32 in network byte order.
func ipToUint32(ip string) uint32 {
	parsed := net.ParseIP(ip).To4()
	return binary.BigEndian.Uint32(parsed)
}

func TestCollector_EmitsMetricsWithDirection(t *testing.T) {
	ip := ipToUint32("10.0.1.5")
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{
			{IP: ip, Proto: ebpfpkg.ProtoTCP, Direction: ebpfpkg.DirectionSource}: 42,
			{IP: ip, Proto: ebpfpkg.ProtoTCP, Direction: ebpfpkg.DirectionDest}:   15,
		},
	}
	res := &mockResolver{
		ips: map[string]resolver.PodInfo{
			"10.0.1.5": {Name: "web-abc", Namespace: "default", App: "web"},
		},
	}

	c := NewCollector(reader, res)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	if len(families) == 0 {
		t.Fatal("expected at least one metric family")
	}

	family := families[0]
	if *family.Name != "node_conntrack_ebpf_entries_by_pod" {
		t.Errorf("unexpected metric name: %s", *family.Name)
	}
	if len(family.Metric) != 2 {
		t.Errorf("expected 2 metrics (source + destination), got %d", len(family.Metric))
	}

	// Verify direction label exists on each metric
	for _, metric := range family.Metric {
		hasDirection := false
		for _, label := range metric.Label {
			if *label.Name == "direction" {
				hasDirection = true
				if *label.Value != "source" && *label.Value != "destination" {
					t.Errorf("unexpected direction value: %s", *label.Value)
				}
			}
		}
		if !hasDirection {
			t.Error("expected direction label on metric")
		}
	}
}

func TestCollector_UnresolvedIPGetsUnknownLabels(t *testing.T) {
	ip := ipToUint32("10.0.99.99")
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{
			{IP: ip, Proto: ebpfpkg.ProtoUDP, Direction: ebpfpkg.DirectionSource}: 10,
		},
	}
	res := &mockResolver{ips: map[string]resolver.PodInfo{}}

	c := NewCollector(reader, res)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	if len(families) == 0 {
		t.Fatal("expected metric family")
	}

	metric := families[0].Metric[0]
	for _, label := range metric.Label {
		if *label.Name == "pod" && *label.Value != "unknown" {
			t.Errorf("expected pod=unknown for unresolved IP, got %s", *label.Value)
		}
	}
}

func TestCollector_SkipsZeroCountEntries(t *testing.T) {
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{},
	}
	res := &mockResolver{ips: map[string]resolver.PodInfo{}}

	c := NewCollector(reader, res)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	for _, f := range families {
		if len(f.Metric) > 0 {
			t.Errorf("expected no metrics for empty counters, got %d", len(f.Metric))
		}
	}
}

func TestCollector_AggregatesMultipleUnresolvedIPs(t *testing.T) {
	ip1 := ipToUint32("10.0.99.1")
	ip2 := ipToUint32("10.0.99.2")
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{
			{IP: ip1, Proto: ebpfpkg.ProtoTCP, Direction: ebpfpkg.DirectionSource}: 10,
			{IP: ip2, Proto: ebpfpkg.ProtoTCP, Direction: ebpfpkg.DirectionSource}: 20,
		},
	}
	res := &mockResolver{ips: map[string]resolver.PodInfo{}}

	c := NewCollector(reader, res)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	if len(families) == 0 {
		t.Fatal("expected metric family")
	}

	if len(families[0].Metric) != 1 {
		t.Errorf("expected 1 aggregated metric for unresolved IPs, got %d", len(families[0].Metric))
	}
	if *families[0].Metric[0].Gauge.Value != 30 {
		t.Errorf("expected aggregated value 30, got %v", *families[0].Metric[0].Gauge.Value)
	}
}
```

**Step 3: Verify collector tests pass**

Run: `go test ./pkg/metrics/ -run TestCollector -v`
Expected: 4/4 pass.

---

### Task 8: Update Cilium collector with direction label

**Files:**
- Modify: `pkg/metrics/cilium_collector.go`
- Modify: `pkg/metrics/cilium_collector_test.go`

**Step 1: Update cilium_collector.go for direction label**

Replace the entire content of `pkg/metrics/cilium_collector.go` with:

```go
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"
)

var ciliumDesc = prometheus.NewDesc(
	"node_cilium_ct_entries_by_pod",
	"Number of Cilium conntrack entries per pod, broken down by protocol and direction.",
	[]string{"pod", "namespace", "app", "protocol", "direction"},
	nil,
)

type ciliumMetricKey struct {
	pod, namespace, app, protocol, direction string
}

// CiliumCollector implements prometheus.Collector for per-pod Cilium CT metrics.
type CiliumCollector struct {
	reader   ebpfpkg.CiliumReader
	resolver resolver.Resolver
}

// NewCiliumCollector creates a new CiliumCollector.
func NewCiliumCollector(reader ebpfpkg.CiliumReader, resolver resolver.Resolver) *CiliumCollector {
	return &CiliumCollector{reader: reader, resolver: resolver}
}

// Describe sends the metric descriptor.
func (c *CiliumCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- ciliumDesc
}

// Collect reads Cilium CT maps, resolves pods by IP, aggregates by label set, and emits metrics.
func (c *CiliumCollector) Collect(ch chan<- prometheus.Metric) {
	counts, err := c.reader.ReadCounts()
	if err != nil {
		log.Errorf("Failed to read Cilium CT maps: %v", err)
		ch <- prometheus.NewInvalidMetric(ciliumDesc, err)
		return
	}

	aggregated := make(map[ciliumMetricKey]float64)

	for key, count := range counts {
		if count <= 0 {
			continue
		}

		podName := "unknown"
		namespace := "unknown"
		app := "unknown"

		info, ok := c.resolver.ResolveByIP(key.IP)
		if ok {
			podName = info.Name
			namespace = info.Namespace
			app = info.App
		}

		mk := ciliumMetricKey{
			pod:       podName,
			namespace: namespace,
			app:       app,
			protocol:  key.Protocol,
			direction: key.Direction,
		}
		aggregated[mk] += float64(count)
	}

	for mk, total := range aggregated {
		metric, err := prometheus.NewConstMetric(
			ciliumDesc,
			prometheus.GaugeValue,
			total,
			mk.pod, mk.namespace, mk.app, mk.protocol, mk.direction,
		)
		if err != nil {
			log.Errorf("Failed to create Cilium metric: %v", err)
			continue
		}
		ch <- metric
	}
}
```

**Step 2: Update cilium_collector_test.go for direction**

Replace the entire content of `pkg/metrics/cilium_collector_test.go` with:

```go
package metrics

import (
	"testing"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"

	"github.com/prometheus/client_golang/prometheus"
)

type mockCiliumReader struct {
	counts map[ebpfpkg.CiliumCountKey]int64
	err    error
}

func (m *mockCiliumReader) ReadCounts() (map[ebpfpkg.CiliumCountKey]int64, error) {
	return m.counts, m.err
}

func (m *mockCiliumReader) Close() error { return nil }

func TestCiliumCollector_EmitsMetricsWithDirection(t *testing.T) {
	reader := &mockCiliumReader{
		counts: map[ebpfpkg.CiliumCountKey]int64{
			{IP: "10.0.1.5", Protocol: "tcp", Direction: "source"}:      100,
			{IP: "10.0.1.5", Protocol: "tcp", Direction: "destination"}: 50,
		},
	}
	res := &mockResolver{
		ips: map[string]resolver.PodInfo{
			"10.0.1.5": {Name: "web-abc", Namespace: "default", App: "web"},
		},
	}

	c := NewCiliumCollector(reader, res)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	if len(families) == 0 {
		t.Fatal("expected at least one metric family")
	}

	family := families[0]
	if *family.Name != "node_cilium_ct_entries_by_pod" {
		t.Errorf("unexpected metric name: %s", *family.Name)
	}
	if len(family.Metric) != 2 {
		t.Errorf("expected 2 metrics (source + destination), got %d", len(family.Metric))
	}

	// Verify direction label exists
	for _, metric := range family.Metric {
		hasDirection := false
		for _, label := range metric.Label {
			if *label.Name == "direction" {
				hasDirection = true
			}
		}
		if !hasDirection {
			t.Error("expected direction label on metric")
		}
	}
}

func TestCiliumCollector_UnresolvedIPGetsUnknownLabels(t *testing.T) {
	reader := &mockCiliumReader{
		counts: map[ebpfpkg.CiliumCountKey]int64{
			{IP: "10.0.99.99", Protocol: "tcp", Direction: "source"}: 50,
		},
	}
	res := &mockResolver{ips: map[string]resolver.PodInfo{}}

	c := NewCiliumCollector(reader, res)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	if len(families) == 0 {
		t.Fatal("expected metric family")
	}

	metric := families[0].Metric[0]
	for _, label := range metric.Label {
		if *label.Name == "pod" && *label.Value != "unknown" {
			t.Errorf("expected pod=unknown for unresolved IP, got %s", *label.Value)
		}
	}
}

func TestCiliumCollector_AggregatesMultipleUnresolvedIPs(t *testing.T) {
	reader := &mockCiliumReader{
		counts: map[ebpfpkg.CiliumCountKey]int64{
			{IP: "10.0.99.1", Protocol: "tcp", Direction: "source"}: 30,
			{IP: "10.0.99.2", Protocol: "tcp", Direction: "source"}: 20,
			{IP: "10.0.99.3", Protocol: "tcp", Direction: "source"}: 50,
		},
	}
	res := &mockResolver{ips: map[string]resolver.PodInfo{}}

	c := NewCiliumCollector(reader, res)
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	if len(families) == 0 {
		t.Fatal("expected metric family")
	}

	// Three unresolved IPs with same protocol and direction should aggregate into one metric
	if len(families[0].Metric) != 1 {
		t.Errorf("expected 1 aggregated metric for unresolved IPs, got %d", len(families[0].Metric))
	}
	if *families[0].Metric[0].Gauge.Value != 100 {
		t.Errorf("expected aggregated value 100, got %v", *families[0].Metric[0].Gauge.Value)
	}
}
```

**Step 3: Verify all metric tests pass**

Run: `go test ./pkg/metrics/ -v`
Expected: 7/7 pass (4 collector + 3 cilium_collector).

---

### Task 9: Update cmd/main.go for NODE_IP

**Files:**
- Modify: `cmd/main.go`

**Step 1: Add NODE_IP handling**

After line 78 (after `podResolver := resolver.NewPodResolver(...)`) in `cmd/main.go`, add:

```go
	// Register node IP for node traffic attribution
	nodeIP := os.Getenv("NODE_IP")
	if nodeIP != "" {
		podResolver.SetNodeInfo(nodeIP, nodeName)
		log.Infof("Node IP %s registered for attribution", nodeIP)
	}
```

**Step 2: Verify main compiles**

Run: `go vet ./cmd/...`
Expected: Pass.

---

### Task 10: Update DaemonSet manifest for NODE_IP

**Files:**
- Modify: `deploy/daemonset.yaml`

**Step 1: Add NODE_IP environment variable**

In `deploy/daemonset.yaml`, add after the `NODE_NAME` env var (after line 61):

```yaml
            - name: NODE_IP
              valueFrom:
                fieldRef:
                  fieldPath: status.hostIP
```

---

### Task 11: Final verification

**Step 1: Run go vet**

Run: `go vet ./...`
Expected: 0 errors.

**Step 2: Run all tests**

Run: `go test ./pkg/... -v`
Expected: 15/15 pass (8 resolver + 7 metrics).

**Step 3: Check IDE diagnostics**

Run IDE diagnostics check.
Expected: 0 errors.
