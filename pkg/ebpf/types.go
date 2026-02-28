package ebpf

// Protocol bucket constants — must match BPF C defines in conntrack.c.
const (
	ProtoTCP   uint8 = 0
	ProtoUDP   uint8 = 1
	ProtoOther uint8 = 2
)

// ProtoNames maps protocol bucket constants to Prometheus label values.
var ProtoNames = map[uint8]string{
	ProtoTCP:   "tcp",
	ProtoUDP:   "udp",
	ProtoOther: "other",
}

// MapKey matches the BPF map key struct in conntrack.c.
type MapKey struct {
	NetnsInode uint32
	Proto      uint8
	Pad        [3]uint8
}

// MapReader reads counters from the BPF map.
type MapReader interface {
	ReadCounters() (map[MapKey]int64, error)
	Close() error
}
