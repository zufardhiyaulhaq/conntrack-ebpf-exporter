package metrics

import (
	"encoding/binary"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"
)

const (
	metricName = "node_conntrack_ebpf_entries_by_pod"
	metricHelp = "Number of conntrack entries per pod, broken down by protocol and direction."
)

var desc = prometheus.NewDesc(
	metricName,
	metricHelp,
	[]string{"pod", "namespace", "app", "protocol", "direction"},
	nil,
)

type conntrackMetricKey struct {
	pod, namespace, app, protocol, direction string
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

// Collect reads BPF counters, resolves pods by IP, aggregates by label set, and emits metrics.
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

		protoName, ok := ebpfpkg.ProtoNames[key.Proto]
		if !ok {
			protoName = "other"
		}

		dirName, ok := ebpfpkg.DirectionNames[key.Direction]
		if !ok {
			dirName = "unknown"
		}

		mk := conntrackMetricKey{
			pod:       podName,
			namespace: namespace,
			app:       app,
			protocol:  protoName,
			direction: dirName,
		}
		aggregated[mk] += float64(count)
	}

	for mk, total := range aggregated {
		metric, err := prometheus.NewConstMetric(
			desc,
			prometheus.GaugeValue,
			total,
			mk.pod, mk.namespace, mk.app, mk.protocol, mk.direction,
		)
		if err != nil {
			log.Errorf("Failed to create metric: %v", err)
			continue
		}
		ch <- metric
	}
}

// uint32ToIP converts a uint32 in network byte order to a dotted-decimal IP string.
func uint32ToIP(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
