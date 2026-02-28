# Bugfix Pass Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix 7 bugs found during code audit: duplicate metric emission, Cilium double-counting, state bucket drift, IP cache corruption, hardcoded x86 arch, small BPF map, and missing informer resync.

**Architecture:** All fixes are localized changes to existing files. No new files. The BPF C program simplifies from 6 state buckets to 3 protocol-only buckets. Both Prometheus collectors aggregate by resolved label set before emitting. The resolver gains IP-recycling-safe cache management.

**Tech Stack:** Go, eBPF C, cilium/ebpf, prometheus/client_golang, client-go informers

---

### Task 1: Simplify BPF state buckets to protocol-only (tcp/udp/other)

The kernel conntrack BPF program currently tracks 6 TCP sub-states. TCP state at insert time differs from delete time, causing state buckets to drift. Simplify to 3 protocol-only buckets which are stable across insert/delete.

**Files:**
- Modify: `bpf/conntrack.c:13-58`
- Modify: `pkg/ebpf/types.go:1-35`
- Modify: `pkg/metrics/collector.go:11-21,40-82`
- Modify: `pkg/metrics/collector_test.go:41-75`

**Step 1: Update BPF C program state defines and get_state_bucket**

Replace the 6 state defines and the full `get_state_bucket` function in `bpf/conntrack.c`. Change lines 13-58 to:

```c
// Protocol buckets — must match Go constants in types.go
#define PROTO_TCP   0
#define PROTO_UDP   1
#define PROTO_OTHER 2

struct map_key {
    __u32 netns_inode;
    __u8  proto;
    __u8  pad[3];
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
```

Also update the two call sites — `count_insert` and `count_delete` — to call `get_proto_bucket` instead of `get_state_bucket`:

In `count_insert` (around line 72): change `key.state = get_state_bucket(ct);` to `key.proto = get_proto_bucket(ct);`

In `count_delete` (around line 86): change `key.state = get_state_bucket(ct);` to `key.proto = get_proto_bucket(ct);`

**Step 2: Update Go types to match new BPF layout**

Replace the entire contents of `pkg/ebpf/types.go` with:

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

// MapKey matches the BPF map key struct in conntrack.c.
type MapKey struct {
	NetnsInode uint32
	Proto      uint8
	Pad        [3]uint8
}

// MapReader reads counters from the BPF map.
type MapReader interface {
	ReadCounters() (map[MapKey]int64, error)
	Close() error
}
```

**Step 3: Update kernel conntrack collector to use "protocol" label**

Replace the full contents of `pkg/metrics/collector.go` with:

```go
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"
)

const (
	metricName = "node_conntrack_ebpf_entries_by_pod"
	metricHelp = "Number of conntrack entries per pod, broken down by protocol."
)

var desc = prometheus.NewDesc(
	metricName,
	metricHelp,
	[]string{"pod", "namespace", "app", "protocol"},
	nil,
)

type conntrackMetricKey struct {
	pod, namespace, app, protocol string
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

// Collect reads BPF counters, resolves pods, aggregates by label set, and emits metrics.
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

		podName := "unknown"
		namespace := "unknown"
		app := "unknown"

		info, ok := c.resolver.Resolve(key.NetnsInode)
		if ok {
			podName = info.Name
			namespace = info.Namespace
			app = info.App
		}

		protoName, ok := ebpfpkg.ProtoNames[key.Proto]
		if !ok {
			protoName = "other"
		}

		mk := conntrackMetricKey{pod: podName, namespace: namespace, app: app, protocol: protoName}
		aggregated[mk] += float64(count)
	}

	for mk, total := range aggregated {
		metric, err := prometheus.NewConstMetric(
			desc,
			prometheus.GaugeValue,
			total,
			mk.pod, mk.namespace, mk.app, mk.protocol,
		)
		if err != nil {
			log.Errorf("Failed to create metric: %v", err)
			continue
		}
		ch <- metric
	}
}
```

**Step 4: Update kernel conntrack collector tests**

Replace the full contents of `pkg/metrics/collector_test.go` with:

```go
package metrics

import (
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

func TestCollector_EmitsMetricsForKnownPod(t *testing.T) {
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{
			{NetnsInode: 100, Proto: ebpfpkg.ProtoTCP}: 42,
			{NetnsInode: 100, Proto: ebpfpkg.ProtoUDP}: 15,
		},
	}
	res := &mockResolver{
		pods: map[uint32]resolver.PodInfo{
			100: {Name: "web-abc", Namespace: "default", App: "web"},
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
		t.Errorf("expected 2 metrics, got %d", len(family.Metric))
	}
}

func TestCollector_UnresolvedNetnsGetsUnknownLabels(t *testing.T) {
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{
			{NetnsInode: 999, Proto: ebpfpkg.ProtoUDP}: 10,
		},
	}
	res := &mockResolver{pods: map[uint32]resolver.PodInfo{}}

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
			t.Errorf("expected pod=unknown for unresolved netns, got %s", *label.Value)
		}
	}
}

func TestCollector_SkipsZeroCountEntries(t *testing.T) {
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{},
	}
	res := &mockResolver{pods: map[uint32]resolver.PodInfo{}}

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

func TestCollector_AggregatesMultipleUnresolvedNetns(t *testing.T) {
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{
			{NetnsInode: 888, Proto: ebpfpkg.ProtoTCP}: 10,
			{NetnsInode: 999, Proto: ebpfpkg.ProtoTCP}: 20,
		},
	}
	res := &mockResolver{pods: map[uint32]resolver.PodInfo{}}

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

	// Two unresolved netns with same protocol should aggregate into one metric
	if len(families[0].Metric) != 1 {
		t.Errorf("expected 1 aggregated metric for unresolved netns, got %d", len(families[0].Metric))
	}
	if *families[0].Metric[0].Gauge.Value != 30 {
		t.Errorf("expected aggregated value 30, got %v", *families[0].Metric[0].Gauge.Value)
	}
}
```

**Step 5: Run tests**

Run: `go test ./pkg/metrics/... -run TestCollector -v`
Expected: All 4 TestCollector tests PASS

Run: `go vet ./pkg/ebpf/...`
Expected: No errors

---

### Task 2: Fix Cilium CT double-counting and collector aggregation

Cilium stores 2 entries per connection (original + reply). Skip reply-direction entries. Also add metric aggregation to prevent duplicate label errors.

**Files:**
- Modify: `pkg/ebpf/cilium.go:94-132`
- Modify: `pkg/metrics/cilium_collector.go:35-72`
- Modify: `pkg/metrics/cilium_collector_test.go`

**Step 1: Skip reply-direction entries in iterateMap**

In `pkg/ebpf/cilium.go`, replace the `iterateMap` method (lines 94-132) with:

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

		podIP := net.IPv4(tuple.SourceAddr[0], tuple.SourceAddr[1], tuple.SourceAddr[2], tuple.SourceAddr[3])

		var proto string
		switch tuple.NextHdr {
		case 6:
			proto = "tcp"
		case 17:
			proto = "udp"
		default:
			proto = "other"
		}

		key := CiliumCountKey{SourceIP: podIP.String(), Protocol: proto}
		result[key]++
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

Also update the `ReadCounts` doc comment (line 76-78) to:

```go
// ReadCounts iterates Cilium's CT maps and returns entry counts grouped by
// source pod IP and protocol. Only original-direction entries are counted
// to avoid double-counting (Cilium stores both original and reply entries).
```

**Step 2: Add aggregation to Cilium collector**

Replace the full contents of `pkg/metrics/cilium_collector.go` with:

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
	"Number of Cilium conntrack entries per pod, broken down by protocol.",
	[]string{"pod", "namespace", "app", "protocol"},
	nil,
)

type ciliumMetricKey struct {
	pod, namespace, app, protocol string
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

		info, ok := c.resolver.ResolveByIP(key.SourceIP)
		if ok {
			podName = info.Name
			namespace = info.Namespace
			app = info.App
		}

		mk := ciliumMetricKey{pod: podName, namespace: namespace, app: app, protocol: key.Protocol}
		aggregated[mk] += float64(count)
	}

	for mk, total := range aggregated {
		metric, err := prometheus.NewConstMetric(
			ciliumDesc,
			prometheus.GaugeValue,
			total,
			mk.pod, mk.namespace, mk.app, mk.protocol,
		)
		if err != nil {
			log.Errorf("Failed to create Cilium metric: %v", err)
			continue
		}
		ch <- metric
	}
}
```

**Step 3: Update Cilium collector tests to cover aggregation**

Replace the full contents of `pkg/metrics/cilium_collector_test.go` with:

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

func TestCiliumCollector_EmitsMetricsForKnownPod(t *testing.T) {
	reader := &mockCiliumReader{
		counts: map[ebpfpkg.CiliumCountKey]int64{
			{SourceIP: "10.0.1.5", Protocol: "tcp"}: 100,
			{SourceIP: "10.0.1.5", Protocol: "udp"}: 20,
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
		t.Errorf("expected 2 metrics, got %d", len(family.Metric))
	}
}

func TestCiliumCollector_UnresolvedIPGetsUnknownLabels(t *testing.T) {
	reader := &mockCiliumReader{
		counts: map[ebpfpkg.CiliumCountKey]int64{
			{SourceIP: "10.0.99.99", Protocol: "tcp"}: 50,
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
			{SourceIP: "10.0.99.1", Protocol: "tcp"}: 30,
			{SourceIP: "10.0.99.2", Protocol: "tcp"}: 20,
			{SourceIP: "10.0.99.3", Protocol: "tcp"}: 50,
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

	// Three unresolved IPs with same protocol should aggregate into one metric
	if len(families[0].Metric) != 1 {
		t.Errorf("expected 1 aggregated metric for unresolved IPs, got %d", len(families[0].Metric))
	}
	if *families[0].Metric[0].Gauge.Value != 100 {
		t.Errorf("expected aggregated value 100, got %v", *families[0].Metric[0].Gauge.Value)
	}
}
```

**Step 4: Run tests**

Run: `go test ./pkg/metrics/... -v`
Expected: All 7 tests PASS (4 kernel collector + 3 Cilium collector)

---

### Task 3: Fix IP cache staleness and corruption

When pod IPs get recycled between pods, the IP cache can become inconsistent. Fix `AddPodIP` to clean up old mappings and `RemovePod` to verify ownership before deleting.

**Files:**
- Modify: `pkg/resolver/resolver.go:221-261`
- Modify: `pkg/resolver/resolver_test.go` (add new tests)

**Step 1: Add failing test for IP recycling**

Add these two tests at the end of `pkg/resolver/resolver_test.go`:

```go
func TestAddPodIP_RecycledIPCleansUpOldPod(t *testing.T) {
	r := &PodResolver{
		cache: make(map[uint32]PodInfo),
		ipCache: map[string]PodInfo{
			"10.0.1.5": {Name: "old-pod", Namespace: "default", App: "old"},
		},
		podInodes: make(map[string][]uint32),
		podIPs: map[string][]string{
			"default/old-pod": {"10.0.1.5"},
		},
		mu: sync.RWMutex{},
	}

	// New pod gets the same IP (recycled)
	r.AddPodIP("new-pod", "default", "new", "10.0.1.5")

	// IP should now resolve to new pod
	info, ok := r.ResolveByIP("10.0.1.5")
	if !ok {
		t.Fatal("expected IP to resolve")
	}
	if info.Name != "new-pod" {
		t.Errorf("expected new-pod, got %s", info.Name)
	}

	// Old pod's IP list should be cleaned up
	if ips := r.podIPs["default/old-pod"]; len(ips) != 0 {
		t.Errorf("expected old pod IP list to be empty, got %v", ips)
	}
}

func TestRemovePod_DoesNotDeleteRecycledIP(t *testing.T) {
	r := &PodResolver{
		cache: make(map[uint32]PodInfo),
		ipCache: map[string]PodInfo{
			// IP was recycled: ipCache points to new-pod
			"10.0.1.5": {Name: "new-pod", Namespace: "default", App: "new"},
		},
		podInodes: make(map[string][]uint32),
		podIPs: map[string][]string{
			// But old-pod's list still references the IP (stale)
			"default/old-pod": {"10.0.1.5"},
		},
		mu: sync.RWMutex{},
	}

	// Removing old-pod should NOT delete the IP mapping (it belongs to new-pod now)
	r.RemovePod("old-pod", "default")

	info, ok := r.ResolveByIP("10.0.1.5")
	if !ok {
		t.Fatal("expected IP to still resolve after removing old pod")
	}
	if info.Name != "new-pod" {
		t.Errorf("expected new-pod, got %s", info.Name)
	}
}
```

**Step 2: Run the new tests to verify they fail**

Run: `go test ./pkg/resolver/... -run "TestAddPodIP_RecycledIP|TestRemovePod_DoesNotDeleteRecycledIP" -v`
Expected: Both tests FAIL

**Step 3: Fix AddPodIP to clean up recycled IPs**

In `pkg/resolver/resolver.go`, replace the `AddPodIP` method (lines 222-241) with:

```go
// AddPodIP stores the pod IP → PodInfo mapping for Cilium CT resolution.
// If the IP was previously mapped to a different pod, the old mapping is cleaned up.
func (r *PodResolver) AddPodIP(name, namespace, app, podIP string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	podKey := namespace + "/" + name

	// Skip if IP already cached for this pod
	if ips, exists := r.podIPs[podKey]; exists {
		for _, ip := range ips {
			if ip == podIP {
				return
			}
		}
	}

	// If this IP was previously mapped to a different pod, clean up the old mapping
	if oldInfo, exists := r.ipCache[podIP]; exists {
		oldKey := oldInfo.Namespace + "/" + oldInfo.Name
		if oldKey != podKey {
			r.podIPs[oldKey] = removeString(r.podIPs[oldKey], podIP)
			log.Debugf("IP %s recycled from pod %s to %s", podIP, oldKey, podKey)
		}
	}

	info := PodInfo{Name: name, Namespace: namespace, App: app}
	r.ipCache[podIP] = info
	r.podIPs[podKey] = append(r.podIPs[podKey], podIP)
	log.Debugf("Resolved pod %s/%s → IP %s", namespace, name, podIP)
}
```

**Step 4: Fix RemovePod to verify ownership before deleting IP entries**

In `pkg/resolver/resolver.go`, replace the `RemovePod` method (lines 244-261) with:

```go
// RemovePod removes all netns inode and IP mappings for the given pod.
func (r *PodResolver) RemovePod(name, namespace string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	podKey := namespace + "/" + name

	for _, inode := range r.podInodes[podKey] {
		delete(r.cache, inode)
	}
	delete(r.podInodes, podKey)

	for _, ip := range r.podIPs[podKey] {
		// Only delete from ipCache if the mapping still belongs to this pod.
		// The IP may have been recycled to another pod already.
		if info, exists := r.ipCache[ip]; exists {
			if info.Namespace+"/"+info.Name == podKey {
				delete(r.ipCache, ip)
			}
		}
	}
	delete(r.podIPs, podKey)

	log.Debugf("Removed pod %s/%s from resolver", namespace, name)
}
```

**Step 5: Add the removeString helper function**

Add this helper at the end of `pkg/resolver/resolver.go` (after `ResolveByIP`):

```go
// removeString removes the first occurrence of s from the slice.
func removeString(slice []string, s string) []string {
	for i, v := range slice {
		if v == s {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}
```

**Step 6: Run all resolver tests**

Run: `go test ./pkg/resolver/... -v`
Expected: All 7 tests PASS (5 existing + 2 new)

---

### Task 4: Detect architecture for BPF compilation

The BPF compiler flag `-D__TARGET_ARCH_x86` is hardcoded. Detect the actual architecture from `runtime.GOARCH`.

**Files:**
- Modify: `pkg/ebpf/loader.go:1-15,57-67`

**Step 1: Add runtime import and architecture map**

In `pkg/ebpf/loader.go`, add `"runtime"` to the import block (after `"os/exec"`, line 9).

**Step 2: Replace the hardcoded architecture flag**

In `pkg/ebpf/loader.go`, replace the clang command construction (lines 58-67) with:

```go
	// Compile BPF program against the kernel-matched vmlinux.h
	log.Info("Compiling BPF program...")
	targetArch := "x86"
	switch runtime.GOARCH {
	case "arm64":
		targetArch = "arm64"
	case "s390x":
		targetArch = "s390"
	case "ppc64le":
		targetArch = "powerpc"
	}
	cmd = exec.Command("clang",
		"-O2", "-g",
		"-target", "bpf",
		"-D__TARGET_ARCH_"+targetArch,
		"-I/tmp",         // vmlinux.h
		"-I/usr/include", // bpf/bpf_helpers.h etc.
		"-c", bpfSourcePath,
		"-o", compiledPath,
	)
```

**Step 3: Run go vet**

Run: `go vet ./pkg/ebpf/...`
Expected: No errors

---

### Task 5: Set informer resync period

A resync period of 0 means the informer never re-syncs. Set it to 5 minutes for eventual consistency.

**Files:**
- Modify: `pkg/resolver/resolver.go:4-19,107-108`

**Step 1: Add time import**

In `pkg/resolver/resolver.go`, add `"time"` to the import block (after `"sync"`, line 10).

**Step 2: Change resync period**

In `pkg/resolver/resolver.go`, change line 108 from:

```go
	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset, 0,
```

to:

```go
	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset, 5*time.Minute,
```

**Step 3: Run go vet**

Run: `go vet ./pkg/resolver/...`
Expected: No errors

---

### Task 6: Final verification

Run all tests and vet across the entire project to confirm nothing is broken.

**Step 1: Run go vet on all packages**

Run: `go vet ./...`
Expected: No errors (note: loader.go and cilium.go have linux build tags, so on macOS they may be skipped — that is expected)

**Step 2: Run all tests**

Run: `go test ./pkg/... -v`
Expected: All tests PASS:
- `pkg/resolver`: 7 tests (TestResolve_KnownPod, TestResolve_UnknownPod, TestAddPod, TestRemovePod, TestResolveByIP, TestAddPodIP_RecycledIPCleansUpOldPod, TestRemovePod_DoesNotDeleteRecycledIP)
- `pkg/metrics`: 7 tests (TestCollector_EmitsMetricsForKnownPod, TestCollector_UnresolvedNetnsGetsUnknownLabels, TestCollector_SkipsZeroCountEntries, TestCollector_AggregatesMultipleUnresolvedNetns, TestCiliumCollector_EmitsMetricsForKnownPod, TestCiliumCollector_UnresolvedIPGetsUnknownLabels, TestCiliumCollector_AggregatesMultipleUnresolvedIPs)

**Step 3: Check IDE diagnostics**

Run IDE diagnostics tool.
Expected: 0 errors.

---

## Summary of all file changes

| File | Change |
|------|--------|
| `bpf/conntrack.c` | Simplify 6 state defines → 3 protocol defines; simplify `get_state_bucket` → `get_proto_bucket`; increase `max_entries` 8192 → 65536; rename `key.state` → `key.proto` |
| `pkg/ebpf/types.go` | Replace 6 State* constants with 3 Proto* constants; rename `StateNames` → `ProtoNames`; rename `MapKey.State` → `MapKey.Proto` |
| `pkg/ebpf/cilium.go` | Skip reply-direction CT entries (`Flags&0x1 != 0`); simplify to original-direction-only counting |
| `pkg/ebpf/loader.go` | Detect `runtime.GOARCH` for `-D__TARGET_ARCH_*` flag; add `"runtime"` import |
| `pkg/metrics/collector.go` | Rename label "state" → "protocol"; aggregate by resolved label set before emitting; add `conntrackMetricKey` struct |
| `pkg/metrics/cilium_collector.go` | Aggregate by resolved label set before emitting; add `ciliumMetricKey` struct |
| `pkg/metrics/collector_test.go` | Update to use `Proto` field; add `TestCollector_AggregatesMultipleUnresolvedNetns` |
| `pkg/metrics/cilium_collector_test.go` | Add `TestCiliumCollector_AggregatesMultipleUnresolvedIPs` |
| `pkg/resolver/resolver.go` | Fix `AddPodIP` for IP recycling; fix `RemovePod` ownership check; add `removeString` helper; add `"time"` import; set resync to 5min |
| `pkg/resolver/resolver_test.go` | Add `TestAddPodIP_RecycledIPCleansUpOldPod`, `TestRemovePod_DoesNotDeleteRecycledIP` |
