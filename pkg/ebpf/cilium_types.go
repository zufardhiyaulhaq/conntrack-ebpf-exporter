package ebpf

// CiliumCountKey aggregates Cilium conntrack entries by IP, protocol, and direction.
type CiliumCountKey struct {
	IP        string // source or destination IP
	Protocol  string // "tcp", "udp", "other"
	Direction string // "source" or "destination"
}

// CiliumReader reads conntrack entry counts from Cilium's BPF CT maps.
type CiliumReader interface {
	ReadCounts() (map[CiliumCountKey]int64, error)
	Close() error
}
