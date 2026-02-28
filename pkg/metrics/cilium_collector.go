package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"
)

var ciliumDescFull = prometheus.NewDesc(
	"node_cilium_ct_entries_by_pod",
	"Number of Cilium conntrack entries per pod, broken down by protocol and direction.",
	[]string{"pod", "namespace", "app", "protocol", "direction"},
	nil,
)

var ciliumDescSimple = prometheus.NewDesc(
	"node_cilium_ct_entries_by_pod",
	"Number of Cilium conntrack entries per pod.",
	[]string{"pod", "namespace", "app"},
	nil,
)

var ciliumDNSDesc = prometheus.NewDesc(
	"node_cilium_ct_dns_entries_by_pod",
	"Number of Cilium conntrack entries on port 53 (DNS) per pod.",
	[]string{"pod", "namespace", "app"},
	nil,
)

type ciliumMetricKey struct {
	pod, namespace, app, protocol, direction string
}

type ciliumDNSMetricKey struct {
	pod, namespace, app string
}

// CiliumCollector implements prometheus.Collector for per-pod Cilium CT metrics.
type CiliumCollector struct {
	reader    ebpfpkg.CiliumReader
	resolver  resolver.Resolver
	breakdown bool
}

// NewCiliumCollector creates a new CiliumCollector. When breakdown is true,
// metrics include protocol and direction labels; when false, only pod labels.
func NewCiliumCollector(reader ebpfpkg.CiliumReader, resolver resolver.Resolver, breakdown bool) *CiliumCollector {
	return &CiliumCollector{reader: reader, resolver: resolver, breakdown: breakdown}
}

// Describe sends the metric descriptors.
func (c *CiliumCollector) Describe(ch chan<- *prometheus.Desc) {
	if c.breakdown {
		ch <- ciliumDescFull
	} else {
		ch <- ciliumDescSimple
	}
	ch <- ciliumDNSDesc
}

// Collect reads Cilium CT maps, resolves pods by IP, aggregates by label set, and emits metrics.
func (c *CiliumCollector) Collect(ch chan<- prometheus.Metric) {
	result, err := c.reader.ReadCounts()
	if err != nil {
		desc := ciliumDescSimple
		if c.breakdown {
			desc = ciliumDescFull
		}
		log.Errorf("Failed to read Cilium CT maps: %v", err)
		ch <- prometheus.NewInvalidMetric(desc, err)
		return
	}

	// Emit regular CT entry counts.
	aggregated := make(map[ciliumMetricKey]float64)
	var resolved, unresolved int

	for key, count := range result.Counts {
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
			resolved++
		} else {
			unresolved++
		}

		var mk ciliumMetricKey
		if c.breakdown {
			mk = ciliumMetricKey{pod: podName, namespace: namespace, app: app, protocol: key.Protocol, direction: key.Direction}
		} else {
			mk = ciliumMetricKey{pod: podName, namespace: namespace, app: app}
		}
		aggregated[mk] += float64(count)
	}

	log.Debugf("Cilium CT: %d resolved, %d unresolved count keys", resolved, unresolved)

	for mk, total := range aggregated {
		var metric prometheus.Metric
		var err error
		if c.breakdown {
			metric, err = prometheus.NewConstMetric(
				ciliumDescFull,
				prometheus.GaugeValue,
				total,
				mk.pod, mk.namespace, mk.app, mk.protocol, mk.direction,
			)
		} else {
			metric, err = prometheus.NewConstMetric(
				ciliumDescSimple,
				prometheus.GaugeValue,
				total,
				mk.pod, mk.namespace, mk.app,
			)
		}
		if err != nil {
			log.Errorf("Failed to create Cilium metric: %v", err)
			continue
		}
		ch <- metric
	}

	// Emit DNS entry counts.
	dnsAggregated := make(map[ciliumDNSMetricKey]float64)

	for key, count := range result.DNSCounts {
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

		mk := ciliumDNSMetricKey{pod: podName, namespace: namespace, app: app}
		dnsAggregated[mk] += float64(count)
	}

	for mk, total := range dnsAggregated {
		metric, err := prometheus.NewConstMetric(
			ciliumDNSDesc,
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
