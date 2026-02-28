package ebpf

// CiliumCountKey aggregates Cilium conntrack entries by IP, protocol, and direction.
type CiliumCountKey struct {
	IP        string // source or destination IP
	Protocol  string // "tcp", "udp", "other"
	Direction string // "source" or "destination"
}

// CiliumDNSKey aggregates DNS (port 53) conntrack entries by pod IP.
type CiliumDNSKey struct {
	IP string
}

// CiliumReadResult holds both regular and DNS-specific counts from a single pass.
type CiliumReadResult struct {
	Counts    map[CiliumCountKey]int64
	DNSCounts map[CiliumDNSKey]int64 // entries where src or dst port == 53
}

// CiliumReader reads conntrack entry counts from Cilium's BPF CT maps.
type CiliumReader interface {
	ReadCounts() (*CiliumReadResult, error)
	Close() error
}
