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
