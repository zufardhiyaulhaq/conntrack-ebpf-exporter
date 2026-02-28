//go:build linux

package ebpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
)

const (
	ciliumCT4MapName    = "cilium_ct4_glob"
	ciliumCTAny4MapName = "cilium_ct_any4_"
	dnsPort             = 53
)

// ciliumCT4Tuple matches Cilium's struct ipv4_ct_tuple (14 bytes).
// Field order: daddr, saddr, dport, sport, nexthdr, flags.
type ciliumCT4Tuple struct {
	DestAddr   [4]byte
	SourceAddr [4]byte
	DestPort   uint16
	SourcePort uint16
	NextHdr    uint8
	Flags      uint8
}

// CiliumMapReader reads Cilium's conntrack BPF maps and counts entries per source and destination IP.
type CiliumMapReader struct {
	ct4Map  *ebpf.Map
	any4Map *ebpf.Map
}

// NewCiliumReader finds and opens Cilium's CT maps. Returns an error if the
// primary CT4 map is not found (Cilium not running).
func NewCiliumReader() (*CiliumMapReader, error) {
	ct4, err := findBPFMapByName(ciliumCT4MapName)
	if err != nil {
		return nil, fmt.Errorf("cilium CT4 map not found (is Cilium running?): %w", err)
	}

	// any4 is optional — handles ICMP and other non-TCP/UDP
	any4, _ := findBPFMapByName(ciliumCTAny4MapName)

	log.Info("Cilium conntrack maps opened")
	return &CiliumMapReader{ct4Map: ct4, any4Map: any4}, nil
}

func findBPFMapByName(name string) (*ebpf.Map, error) {
	id := ebpf.MapID(0)
	for {
		nextID, err := ebpf.MapGetNextID(id)
		if err != nil {
			return nil, fmt.Errorf("map %q not found", name)
		}
		id = nextID

		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err != nil {
			m.Close()
			continue
		}
		if info.Name == name {
			return m, nil
		}
		m.Close()
	}
}

// ReadCounts iterates Cilium's CT maps and returns entry counts grouped by
// IP, protocol, and direction, plus DNS-specific counts for port 53 entries.
func (r *CiliumMapReader) ReadCounts() (*CiliumReadResult, error) {
	result := &CiliumReadResult{
		Counts:    make(map[CiliumCountKey]int64),
		DNSCounts: make(map[CiliumDNSKey]int64),
	}

	if err := r.iterateMap(r.ct4Map, result); err != nil {
		return nil, fmt.Errorf("reading Cilium CT4 map: %w", err)
	}
	if r.any4Map != nil {
		if err := r.iterateMap(r.any4Map, result); err != nil {
			log.Warnf("Error reading Cilium any4 map: %v", err)
		}
	}

	return result, nil
}

// binKey is a compact, allocation-free map key for aggregation.
// Using fixed-size fields avoids string allocations in the hot loop.
type binKey struct {
	ip        [4]byte
	proto     uint8 // 6=tcp, 17=udp, 0=other
	direction uint8 // 0=source, 1=destination
}

func (r *CiliumMapReader) iterateMap(m *ebpf.Map, result *CiliumReadResult) error {
	var tuple ciliumCT4Tuple
	var value [56]byte // CT entry value — we don't parse it, just need the key

	// Phase 1: Aggregate using binary keys (zero allocations per entry).
	binCounts := make(map[binKey]int64)
	dnsCounts := make(map[[4]byte]int64)

	iter := m.Iterate()
	for iter.Next(&tuple, &value) {
		// Only count original-direction entries (Flags bit 0 == 0).
		// Cilium stores two entries per connection (original + reply).
		// Counting both would double the metrics.
		if tuple.Flags&0x1 != 0 {
			continue
		}

		// Separate DNS (port 53) entries from regular counts.
		// Ports in BPF map are network byte order; ntohs swaps to host order.
		if ntohs(tuple.SourcePort) == dnsPort || ntohs(tuple.DestPort) == dnsPort {
			dnsCounts[tuple.SourceAddr]++
			dnsCounts[tuple.DestAddr]++
		} else {
			binCounts[binKey{ip: tuple.SourceAddr, proto: tuple.NextHdr, direction: 0}]++
			binCounts[binKey{ip: tuple.DestAddr, proto: tuple.NextHdr, direction: 1}]++
		}
	}

	if err := iter.Err(); err != nil {
		if errors.Is(err, ebpf.ErrIterationAborted) {
			log.Warn("Cilium CT map iteration aborted, partial results returned")
		} else {
			return err
		}
	}

	// Phase 2: Convert only unique aggregated keys to strings.
	for bk, count := range binCounts {
		var proto string
		switch bk.proto {
		case 6:
			proto = "tcp"
		case 17:
			proto = "udp"
		default:
			proto = "other"
		}

		var direction string
		if bk.direction == 0 {
			direction = "source"
		} else {
			direction = "destination"
		}

		ip := fmt.Sprintf("%d.%d.%d.%d", bk.ip[0], bk.ip[1], bk.ip[2], bk.ip[3])
		sk := CiliumCountKey{IP: ip, Protocol: proto, Direction: direction}
		result.Counts[sk] += count
	}

	for addr, count := range dnsCounts {
		ip := fmt.Sprintf("%d.%d.%d.%d", addr[0], addr[1], addr[2], addr[3])
		result.DNSCounts[CiliumDNSKey{IP: ip}] += count
	}

	return nil
}

// ntohs converts a uint16 from network byte order (big-endian) to host byte order.
func ntohs(v uint16) uint16 {
	return (v >> 8) | (v << 8)
}

// Close closes the Cilium CT map file descriptors.
func (r *CiliumMapReader) Close() error {
	var errs []error
	if r.ct4Map != nil {
		errs = append(errs, r.ct4Map.Close())
	}
	if r.any4Map != nil {
		errs = append(errs, r.any4Map.Close())
	}
	return errors.Join(errs...)
}
