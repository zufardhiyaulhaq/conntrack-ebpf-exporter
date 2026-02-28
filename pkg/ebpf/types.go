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

// Direction constants — must match BPF C defines in conntrack.c.
const (
	DirectionSource uint8 = 0
	DirectionDest   uint8 = 1
)

// DirectionNames maps direction constants to Prometheus label values.
var DirectionNames = map[uint8]string{
	DirectionSource: "source",
	DirectionDest:   "destination",
}

// MapKey matches the BPF map key struct in conntrack.c.
type MapKey struct {
	IP        uint32
	Proto     uint8
	Direction uint8
	Pad       [2]uint8
}

// MapReader reads counters from the BPF map.
type MapReader interface {
	ReadCounters() (map[MapKey]int64, error)
	Close() error
}
