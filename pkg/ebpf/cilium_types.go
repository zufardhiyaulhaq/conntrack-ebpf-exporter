package ebpf

// CiliumCountKey aggregates Cilium conntrack entries by source IP and protocol.
type CiliumCountKey struct {
	SourceIP string // e.g. "10.0.1.2"
	Protocol string // "tcp", "udp", "other"
}

// CiliumReader reads conntrack entry counts from Cilium's BPF CT maps.
type CiliumReader interface {
	ReadCounts() (map[CiliumCountKey]int64, error)
	Close() error
}
