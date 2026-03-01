# Conntrack BPF DNS Separation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add port reading to the kernel conntrack kprobe so it separates DNS (port 53) from non-DNS traffic, matching the Cilium system's behavior.

**Architecture:** Read source/dest ports from `nf_conn` in the existing kprobes. Route DNS entries (port 53) to a new `dns_counts` BPF map, non-DNS to the existing `conntrack_counts` map. Propagate the new DNS data through the Go types, loader, and Prometheus collector.

**Tech Stack:** BPF C (kprobe), Go, cilium/ebpf, prometheus/client_golang

---

### Task 1: Add DNS map and port reading to BPF program

**Files:**
- Modify: `bpf/conntrack.c`

**Step 1: Add dns_key struct and dns_counts map after the existing conntrack_counts map (after line 34)**

Add this code after the `conntrack_counts` map definition:

```c
#define DNS_PORT __bpf_constant_htons(53)

struct dns_key {
    __u32 ip;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct dns_key);
    __type(value, __s64);
} dns_counts SEC(".maps");
```

**Step 2: Add update_dns_count helper after update_count (after line 62)**

```c
static __always_inline void update_dns_count(struct dns_key *key, __s64 delta) {
    __s64 *val = bpf_map_lookup_elem(&dns_counts, key);
    if (val) {
        __s64 new_val = __sync_fetch_and_add(val, delta) + delta;
        if (delta < 0 && new_val <= 0) {
            bpf_map_delete_elem(&dns_counts, key);
        }
    } else if (delta > 0) {
        __s64 initval = delta;
        bpf_map_update_elem(&dns_counts, key, &initval, BPF_ANY);
    }
}
```

**Step 3: Modify count_entries to read ports and split DNS/non-DNS**

Replace the `count_entries` function (lines 69-86) with:

```c
static __always_inline void count_entries(struct nf_conn *ct, __s64 delta) {
    __u32 src_ip = BPF_CORE_READ(ct, tuplehash[0].tuple.src.u3.ip);
    __u32 dst_ip = BPF_CORE_READ(ct, tuplehash[0].tuple.dst.u3.ip);
    __be16 src_port = BPF_CORE_READ(ct, tuplehash[0].tuple.src.u.all);
    __be16 dst_port = BPF_CORE_READ(ct, tuplehash[0].tuple.dst.u.all);

    if (src_port == DNS_PORT || dst_port == DNS_PORT) {
        struct dns_key src_dns = { .ip = src_ip };
        struct dns_key dst_dns = { .ip = dst_ip };
        update_dns_count(&src_dns, delta);
        update_dns_count(&dst_dns, delta);
    } else {
        __u8 proto = get_proto_bucket(ct);

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
}
```

**Step 4: Verify BPF compiles (no runtime test — BPF needs kernel)**

Run: `go vet ./bpf/... 2>&1 || echo "BPF is C, not Go — visual review only"`

---

### Task 2: Update Go types and MapReader interface

**Files:**
- Modify: `pkg/ebpf/types.go`

**Step 1: Add DNSMapKey and ConntrackReadResult, update MapReader interface**

Replace the entire file content with:

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

// DNSMapKey matches the dns_key struct in conntrack.c.
type DNSMapKey struct {
	IP uint32
}

// ConntrackReadResult holds both regular and DNS-specific counts.
type ConntrackReadResult struct {
	Counts    map[MapKey]int64
	DNSCounts map[DNSMapKey]int64
}

// MapReader reads counters from the BPF map.
type MapReader interface {
	ReadCounters() (*ConntrackReadResult, error)
	Close() error
}
```

**Step 2: Verify compiles**

Run: `go vet ./pkg/ebpf/...`

Expected: compilation errors in `loader.go` and `collector.go` (they still use old signature) — that's expected, we fix them next.

---

### Task 3: Update Loader to read both maps

**Files:**
- Modify: `pkg/ebpf/loader.go`

**Step 1: Update ReadCounters to return ConntrackReadResult**

Replace the `ReadCounters` method (lines 118-147) with:

```go
// ReadCounters iterates both BPF hash maps and returns regular and DNS counts.
func (l *Loader) ReadCounters() (*ConntrackReadResult, error) {
	counts := make(map[MapKey]int64)
	dnsCounts := make(map[DNSMapKey]int64)

	// Read regular conntrack counts
	m := l.coll.Maps["conntrack_counts"]
	if m == nil {
		return nil, fmt.Errorf("BPF map 'conntrack_counts' not found")
	}

	var key MapKey
	var value int64

	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if value <= 0 {
			continue
		}
		counts[key] = value
	}

	if err := iter.Err(); err != nil {
		if !errors.Is(err, ebpf.ErrIterationAborted) {
			return nil, fmt.Errorf("iterating conntrack_counts map: %w", err)
		}
		log.Warn("conntrack_counts iteration aborted, partial results returned")
	}

	// Read DNS counts
	dm := l.coll.Maps["dns_counts"]
	if dm != nil {
		var dnsKey DNSMapKey
		var dnsValue int64

		dnsIter := dm.Iterate()
		for dnsIter.Next(&dnsKey, &dnsValue) {
			if dnsValue <= 0 {
				continue
			}
			dnsCounts[dnsKey] = dnsValue
		}

		if err := dnsIter.Err(); err != nil {
			if !errors.Is(err, ebpf.ErrIterationAborted) {
				return nil, fmt.Errorf("iterating dns_counts map: %w", err)
			}
			log.Warn("dns_counts iteration aborted, partial results returned")
		}
	}

	return &ConntrackReadResult{Counts: counts, DNSCounts: dnsCounts}, nil
}
```

**Step 2: Verify compiles**

Run: `go vet ./pkg/ebpf/...`

Expected: PASS (loader.go compiles). Collector will still fail — fixed in next task.

---

### Task 4: Update Collector to emit DNS metrics

**Files:**
- Modify: `pkg/metrics/collector.go`

**Step 1: Add DNS metric name constant and dnsDesc field**

Add constant after `conntrackMetricName`:

```go
const (
	conntrackMetricName    = "node_conntrack_ebpf_entries_by_pod"
	conntrackDNSMetricName = "node_conntrack_ebpf_dns_entries_by_pod"
)
```

Add `conntrackDNSMetricKey` struct after `conntrackMetricKey`:

```go
type conntrackDNSMetricKey struct {
	pod, namespace, app string
}
```

Add `dnsDesc` field to `Collector` struct:

```go
type Collector struct {
	reader     ebpfpkg.MapReader
	resolver   resolver.Resolver
	breakdown  bool
	descFull   *prometheus.Desc
	descSimple *prometheus.Desc
	dnsDesc    *prometheus.Desc
}
```

**Step 2: Update NewCollector to create dnsDesc**

Add `dnsDesc` creation in the constructor, after `descSimple`:

```go
		dnsDesc: prometheus.NewDesc(
			conntrackDNSMetricName,
			"Number of conntrack entries on port 53 (DNS) per pod.",
			[]string{"pod", "namespace", "app"},
			constLabels,
		),
```

**Step 3: Update Describe to include dnsDesc**

```go
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	if c.breakdown {
		ch <- c.descFull
	} else {
		ch <- c.descSimple
	}
	ch <- c.dnsDesc
}
```

**Step 4: Update Collect to handle ConntrackReadResult and emit DNS metrics**

Replace the `Collect` method with:

```go
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	result, err := c.reader.ReadCounters()
	if err != nil {
		desc := c.descSimple
		if c.breakdown {
			desc = c.descFull
		}
		log.Errorf("Failed to read BPF counters: %v", err)
		ch <- prometheus.NewInvalidMetric(desc, err)
		return
	}

	// Emit regular CT entry counts.
	aggregated := make(map[conntrackMetricKey]float64)

	for key, count := range result.Counts {
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

		var mk conntrackMetricKey
		if c.breakdown {
			protoName, ok := ebpfpkg.ProtoNames[key.Proto]
			if !ok {
				protoName = "other"
			}
			dirName, ok := ebpfpkg.DirectionNames[key.Direction]
			if !ok {
				dirName = "unknown"
			}
			mk = conntrackMetricKey{
				pod:       podName,
				namespace: namespace,
				app:       app,
				protocol:  protoName,
				direction: dirName,
			}
		} else {
			mk = conntrackMetricKey{
				pod:       podName,
				namespace: namespace,
				app:       app,
			}
		}
		aggregated[mk] += float64(count)
	}

	for mk, total := range aggregated {
		var metric prometheus.Metric
		var err error
		if c.breakdown {
			metric, err = prometheus.NewConstMetric(
				c.descFull,
				prometheus.GaugeValue,
				total,
				mk.pod, mk.namespace, mk.app, mk.protocol, mk.direction,
			)
		} else {
			metric, err = prometheus.NewConstMetric(
				c.descSimple,
				prometheus.GaugeValue,
				total,
				mk.pod, mk.namespace, mk.app,
			)
		}
		if err != nil {
			log.Errorf("Failed to create metric: %v", err)
			continue
		}
		ch <- metric
	}

	// Emit DNS entry counts.
	dnsAggregated := make(map[conntrackDNSMetricKey]float64)

	for key, count := range result.DNSCounts {
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

		mk := conntrackDNSMetricKey{pod: podName, namespace: namespace, app: app}
		dnsAggregated[mk] += float64(count)
	}

	for mk, total := range dnsAggregated {
		metric, err := prometheus.NewConstMetric(
			c.dnsDesc,
			prometheus.GaugeValue,
			total,
			mk.pod, mk.namespace, mk.app,
		)
		if err != nil {
			log.Errorf("Failed to create DNS metric: %v", err)
			continue
		}
		ch <- metric
	}
}
```

**Step 5: Verify compiles**

Run: `go vet ./pkg/metrics/...`

Expected: compilation errors in `collector_test.go` (mock uses old interface) — fixed next.

---

### Task 5: Update tests

**Files:**
- Modify: `pkg/metrics/collector_test.go`

**Step 1: Update mockMapReader to return ConntrackReadResult**

Replace the mock (lines 14-23) with:

```go
type mockMapReader struct {
	result *ebpfpkg.ConntrackReadResult
	err    error
}

func (m *mockMapReader) ReadCounters() (*ebpfpkg.ConntrackReadResult, error) {
	return m.result, m.err
}

func (m *mockMapReader) Close() error { return nil }

func newMockConntrackResult(counts map[ebpfpkg.MapKey]int64, dns map[ebpfpkg.DNSMapKey]int64) *ebpfpkg.ConntrackReadResult {
	if dns == nil {
		dns = make(map[ebpfpkg.DNSMapKey]int64)
	}
	return &ebpfpkg.ConntrackReadResult{Counts: counts, DNSCounts: dns}
}
```

**Step 2: Update all existing tests to use new mock**

In `TestCollector_EmitsMetricsWithDirection` (line 51), replace:
```go
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{
```
with:
```go
	reader := &mockMapReader{
		result: newMockConntrackResult(map[ebpfpkg.MapKey]int64{
```
And close the `newMockConntrackResult` call — add `, nil)` after the map closing `}`.

Apply the same pattern to all 4 existing tests:
- `TestCollector_EmitsMetricsWithDirection`: wrap counters map with `newMockConntrackResult(..., nil)`
- `TestCollector_UnresolvedIPGetsUnknownLabels`: same
- `TestCollector_SkipsZeroCountEntries`: same (empty map)
- `TestCollector_AggregatesMultipleUnresolvedIPs`: same

**Step 3: Add DNS test**

Add after the last test:

```go
func TestCollector_EmitsDNSMetric(t *testing.T) {
	ip := ipToUint32("10.0.1.5")
	reader := &mockMapReader{
		result: newMockConntrackResult(
			map[ebpfpkg.MapKey]int64{
				{IP: ip, Proto: ebpfpkg.ProtoUDP, Direction: ebpfpkg.DirectionSource}: 100,
			},
			map[ebpfpkg.DNSMapKey]int64{
				{IP: ip}: 42,
			},
		),
	}
	res := &mockResolver{
		ips: map[string]resolver.PodInfo{
			"10.0.1.5": {Name: "web-abc", Namespace: "default", App: "web"},
		},
	}

	c := NewCollector(reader, res, false, "test-node")
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	var dnsFamily *dto.MetricFamily
	for _, f := range families {
		if *f.Name == "node_conntrack_ebpf_dns_entries_by_pod" {
			dnsFamily = f
		}
	}
	if dnsFamily == nil {
		t.Fatal("DNS metric family not found")
	}
	if len(dnsFamily.Metric) != 1 {
		t.Fatalf("expected 1 DNS metric, got %d", len(dnsFamily.Metric))
	}
	if *dnsFamily.Metric[0].Gauge.Value != 42 {
		t.Errorf("expected DNS value 42, got %v", *dnsFamily.Metric[0].Gauge.Value)
	}
}
```

Note: add `dto "github.com/prometheus/client_model/go"` to the imports.

**Step 4: Run tests**

Run: `go test ./pkg/metrics/... -v`

Expected: all tests PASS (existing + new DNS test).

---
