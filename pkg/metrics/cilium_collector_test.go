package metrics

import (
	"testing"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type mockCiliumReader struct {
	result *ebpfpkg.CiliumReadResult
	err    error
}

func (m *mockCiliumReader) ReadCounts() (*ebpfpkg.CiliumReadResult, error) {
	return m.result, m.err
}

func (m *mockCiliumReader) Close() error { return nil }

func newMockResult(counts map[ebpfpkg.CiliumCountKey]int64, dns map[ebpfpkg.CiliumDNSKey]int64) *ebpfpkg.CiliumReadResult {
	if dns == nil {
		dns = make(map[ebpfpkg.CiliumDNSKey]int64)
	}
	return &ebpfpkg.CiliumReadResult{Counts: counts, DNSCounts: dns}
}

func TestCiliumCollector_EmitsMetricsWithDirection(t *testing.T) {
	reader := &mockCiliumReader{
		result: newMockResult(map[ebpfpkg.CiliumCountKey]int64{
			{IP: "10.0.1.5", Protocol: "tcp", Direction: "source"}:      100,
			{IP: "10.0.1.5", Protocol: "tcp", Direction: "destination"}: 50,
		}, nil),
	}
	res := &mockResolver{
		ips: map[string]resolver.PodInfo{
			"10.0.1.5": {Name: "web-abc", Namespace: "default", App: "web"},
		},
	}

	c := NewCiliumCollector(reader, res, true, "test-node")
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	if len(families) == 0 {
		t.Fatal("expected at least one metric family")
	}

	// Find the CT entries metric (not DNS).
	var family *dto.MetricFamily
	for _, f := range families {
		if *f.Name == "node_cilium_ct_entries_by_pod" {
			family = f
		}
	}
	if family == nil {
		t.Fatal("node_cilium_ct_entries_by_pod not found")
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
		result: newMockResult(map[ebpfpkg.CiliumCountKey]int64{
			{IP: "10.0.99.99", Protocol: "tcp", Direction: "source"}: 50,
		}, nil),
	}
	res := &mockResolver{ips: map[string]resolver.PodInfo{}}

	c := NewCiliumCollector(reader, res, true, "test-node")
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	var family *dto.MetricFamily
	for _, f := range families {
		if *f.Name == "node_cilium_ct_entries_by_pod" {
			family = f
		}
	}
	if family == nil {
		t.Fatal("expected metric family")
	}

	metric := family.Metric[0]
	for _, label := range metric.Label {
		if *label.Name == "pod" && *label.Value != "unknown" {
			t.Errorf("expected pod=unknown for unresolved IP, got %s", *label.Value)
		}
	}
}

func TestCiliumCollector_AggregatesMultipleUnresolvedIPs(t *testing.T) {
	reader := &mockCiliumReader{
		result: newMockResult(map[ebpfpkg.CiliumCountKey]int64{
			{IP: "10.0.99.1", Protocol: "tcp", Direction: "source"}: 30,
			{IP: "10.0.99.2", Protocol: "tcp", Direction: "source"}: 20,
			{IP: "10.0.99.3", Protocol: "tcp", Direction: "source"}: 50,
		}, nil),
	}
	res := &mockResolver{ips: map[string]resolver.PodInfo{}}

	c := NewCiliumCollector(reader, res, true, "test-node")
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	var family *dto.MetricFamily
	for _, f := range families {
		if *f.Name == "node_cilium_ct_entries_by_pod" {
			family = f
		}
	}
	if family == nil {
		t.Fatal("expected metric family")
	}

	// Three unresolved IPs with same protocol and direction should aggregate into one metric
	if len(family.Metric) != 1 {
		t.Errorf("expected 1 aggregated metric for unresolved IPs, got %d", len(family.Metric))
	}
	if *family.Metric[0].Gauge.Value != 100 {
		t.Errorf("expected aggregated value 100, got %v", *family.Metric[0].Gauge.Value)
	}
}

func TestCiliumCollector_EmitsDNSMetric(t *testing.T) {
	reader := &mockCiliumReader{
		result: newMockResult(
			map[ebpfpkg.CiliumCountKey]int64{
				{IP: "10.0.1.5", Protocol: "udp", Direction: "source"}: 100,
			},
			map[ebpfpkg.CiliumDNSKey]int64{
				{IP: "10.0.1.5"}: 42,
			},
		),
	}
	res := &mockResolver{
		ips: map[string]resolver.PodInfo{
			"10.0.1.5": {Name: "web-abc", Namespace: "default", App: "web"},
		},
	}

	c := NewCiliumCollector(reader, res, false, "test-node")
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather error: %v", err)
	}

	var dnsFamily *dto.MetricFamily
	for _, f := range families {
		if *f.Name == "node_cilium_ct_dns_entries_by_pod" {
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
