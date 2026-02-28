package ebpf

// State bucket constants — must match BPF C defines.
const (
	StateTCPEstablished uint8 = 0
	StateTCPTimeWait    uint8 = 1
	StateTCPCloseWait   uint8 = 2
	StateTCPOther       uint8 = 3
	StateUDP            uint8 = 4
	StateOther          uint8 = 5
)

// StateNames maps state bucket constants to human-readable Prometheus label values.
var StateNames = map[uint8]string{
	StateTCPEstablished: "tcp_established",
	StateTCPTimeWait:    "tcp_time_wait",
	StateTCPCloseWait:   "tcp_close_wait",
	StateTCPOther:       "tcp_other",
	StateUDP:            "udp",
	StateOther:          "other",
}

// MapKey matches the BPF map key struct (generated as conntrackMapKey by bpf2go).
type MapKey struct {
	NetnsInode uint32
	State      uint8
	Pad        [3]uint8
}

// MapReader reads counters from the BPF map.
type MapReader interface {
	ReadCounters() (map[MapKey]int64, error)
	Close() error
}
