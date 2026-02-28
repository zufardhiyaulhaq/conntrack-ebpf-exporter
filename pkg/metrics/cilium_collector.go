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

		mk := ciliumMetricKey{pod: podName, namespace: namespace, app: app, protocol: key.Protocol, direction: key.Direction}
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
