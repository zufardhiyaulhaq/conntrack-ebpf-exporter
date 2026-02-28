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

	c := NewCollector(reader, res, true)
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

	c := NewCollector(reader, res, true)
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

	c := NewCollector(reader, res, true)
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

	c := NewCollector(reader, res, true)
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
