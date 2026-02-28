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
