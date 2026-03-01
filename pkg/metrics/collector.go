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
	conntrackMetricName    = "node_conntrack_ebpf_entries_by_pod"
	conntrackDNSMetricName = "node_conntrack_ebpf_dns_entries_by_pod"
)

type conntrackMetricKey struct {
	pod, namespace, app, protocol, direction string
}

type conntrackDNSMetricKey struct {
	pod, namespace, app string
}

// Collector implements prometheus.Collector for per-pod conntrack metrics.
type Collector struct {
	reader     ebpfpkg.MapReader
	resolver   resolver.Resolver
	breakdown  bool
	descFull   *prometheus.Desc
	descSimple *prometheus.Desc
	dnsDesc    *prometheus.Desc
}

// NewCollector creates a new Collector. When breakdown is true, metrics include
// protocol and direction labels; when false, only pod labels.
// nodeName is added as a const label on all metrics.
func NewCollector(reader ebpfpkg.MapReader, resolver resolver.Resolver, breakdown bool, nodeName string) *Collector {
	constLabels := prometheus.Labels{"node": nodeName}
	return &Collector{
		reader:    reader,
		resolver:  resolver,
		breakdown: breakdown,
		descFull: prometheus.NewDesc(
			conntrackMetricName,
			"Number of conntrack entries per pod, broken down by protocol and direction.",
			[]string{"pod", "namespace", "app", "protocol", "direction"},
			constLabels,
		),
		descSimple: prometheus.NewDesc(
			conntrackMetricName,
			"Number of conntrack entries per pod.",
			[]string{"pod", "namespace", "app"},
			constLabels,
		),
		dnsDesc: prometheus.NewDesc(
			conntrackDNSMetricName,
			"Number of conntrack entries on port 53 (DNS) per pod.",
			[]string{"pod", "namespace", "app"},
			constLabels,
		),
	}
}

// Describe sends the metric descriptor.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	if c.breakdown {
		ch <- c.descFull
	} else {
		ch <- c.descSimple
	}
	ch <- c.dnsDesc
}

// Collect reads BPF counters, resolves pods by IP, aggregates by label set, and emits metrics.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	result, err := c.reader.ReadCounters()
	if err != nil {
		desc := c.descSimple
		if c.breakdown {
			desc = c.descFull
		}
		log.Errorf("Failed to read BPF counters: %v", err)
		ch <- prometheus.NewInvalidMetric(desc, err)
		ch <- prometheus.NewInvalidMetric(c.dnsDesc, err)
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

// uint32ToIP converts a uint32 in network byte order to a dotted-decimal IP string.
func uint32ToIP(ip uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ip)
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}
