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
