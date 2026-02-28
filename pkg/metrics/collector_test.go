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

	if len(families[0].Metric) != 1 {
		t.Errorf("expected 1 aggregated metric for unresolved netns, got %d", len(families[0].Metric))
	}
	if *families[0].Metric[0].Gauge.Value != 30 {
		t.Errorf("expected aggregated value 30, got %v", *families[0].Metric[0].Gauge.Value)
	}
}
