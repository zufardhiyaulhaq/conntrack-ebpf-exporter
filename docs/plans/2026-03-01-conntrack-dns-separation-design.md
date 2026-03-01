# Conntrack BPF DNS Separation

## Problem

The kernel conntrack BPF system (`bpf/conntrack.c`) does not read port numbers from `nf_conn`. All connections (HTTP, DNS, gRPC, etc.) are counted together in a single `node_conntrack_ebpf_entries_by_pod` metric. There is no way to separate DNS from non-DNS traffic, unlike the Cilium system which already has this separation.

## Design

Add port reading to the conntrack kprobe so it can separate DNS (port 53) from non-DNS traffic, matching the Cilium system's behavior.

### `bpf/conntrack.c`

- Add `struct dns_key { __u32 ip; }` and a `dns_counts` BPF hash map (key = `dns_key`, value = `__s64`)
- Read source and dest ports from `nf_conn` via `BPF_CORE_READ(ct, tuplehash[0].tuple.src.u.all)` (returns `__be16`)
- In `count_entries()`: if either port == 53 (network byte order), update `dns_counts`; else update `conntrack_counts`. Same if/else exclusion as Cilium — DNS entries do NOT go to the regular map.
- DNS map uses the same +1/-1 delta pattern since kprobes fire on both insert and delete.

### `pkg/ebpf/types.go`

- Add `DNSMapKey` struct with `IP uint32`
- Add `ConntrackReadResult` struct with `Counts map[MapKey]int64` and `DNSCounts map[DNSMapKey]int64`
- Change `MapReader` interface: `ReadCounters()` returns `(*ConntrackReadResult, error)`

### `pkg/ebpf/loader.go`

- `ReadCounters()` reads both `conntrack_counts` and `dns_counts` maps
- Returns `*ConntrackReadResult`

### `pkg/metrics/collector.go`

- Add `dnsDesc` descriptor for `node_conntrack_ebpf_dns_entries_by_pod` (labels: pod, namespace, app; node as constLabel)
- In `Collect()`: emit DNS metrics from `result.DNSCounts`, same pattern as `cilium_collector.go`

### Tests

- Update mocks and assertions for new `ConntrackReadResult` return type

## Overhead

Minimal. The kprobe already fires on every connection insert/delete. Adding 2 extra `BPF_CORE_READ` calls for ports is ~2-3 instructions per event. Map operations stay at 2 per event (just routed to different maps via if/else).
