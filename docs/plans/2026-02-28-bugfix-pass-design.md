# Bugfix Pass Design: conntrack-ebpf-exporter

## Context

After implementing both kernel conntrack (kprobes) and Cilium conntrack (CT map reading), a code audit revealed several bugs ranging from critical metric corruption to medium-severity robustness issues.

## Bugs Addressed

### Critical

1. **Cilium double-counting** — Cilium stores 2 entries per connection (original + reply direction). Both are iterated and counted, producing 2x actual metrics.

2. **Duplicate metric emission** — Both collectors emit raw per-source metrics. When multiple sources resolve to the same label set (e.g. unresolved IPs → `unknown/unknown/unknown/tcp`), Prometheus rejects the duplicates with "collected metric was collected before with the same name and label values".

3. **Kernel conntrack state bucket drift** — TCP state at insert time (SYN_SENT) differs from delete time (TIME_WAIT). Insert and delete target different state buckets, causing unbounded drift per-bucket while total count stays correct.

### High

4. **IP cache staleness** — When a pod restarts with a new IP, the old IP remains in `ipCache` forever.

5. **IP cache cross-pod corruption** — When pod IPs get recycled, `RemovePod` for the old pod deletes the new pod's IP mapping.

### Medium

6. **Hardcoded x86 architecture** — `loader.go` hardcodes `-D__TARGET_ARCH_x86`, breaking ARM nodes.

7. **BPF map too small** — `max_entries=8192` with 6 state buckets. After simplification to 3 buckets, increase to 65536.

8. **Informer never resyncs** — Resync period of 0 means cache never self-heals after missed events.

## Fixes

### Fix 1: Aggregate metrics by label set (Bugs #2)

Both `Collect()` methods aggregate counts into a `map[metricKey]float64` before emitting. This ensures unique label sets per scrape and naturally handles multiple sources resolving to the same pod.

**Files:** `pkg/metrics/collector.go`, `pkg/metrics/cilium_collector.go`

### Fix 2: Skip Cilium reply-direction entries (Bug #1)

In `iterateMap`, skip entries with `Flags&0x1 != 0` (reply direction). Only count original-direction entries — they represent unique connections.

**File:** `pkg/ebpf/cilium.go`

### Fix 3: Simplify state buckets to tcp/udp/other (Bug #3)

Replace 6 TCP sub-state buckets with 3 protocol-only buckets. Protocol doesn't change between insert and delete, so counts remain accurate.

**Files:** `bpf/conntrack.c`, `pkg/ebpf/types.go`, `pkg/metrics/collector.go`, tests

### Fix 4: Fix IP cache staleness and corruption (Bugs #4, #5)

In `AddPodIP`: before writing to `ipCache`, check if the IP was previously mapped to a different pod. If so, clean up the old pod's `podIPs` list.

In `RemovePod`: before deleting from `ipCache`, verify the mapping still belongs to the pod being removed.

**File:** `pkg/resolver/resolver.go`, `pkg/resolver/resolver_test.go`

### Fix 5: Detect architecture for BPF compilation (Bug #6)

Use `runtime.GOARCH` to set the correct `-D__TARGET_ARCH_*` flag. Map `amd64→x86`, `arm64→arm64`.

**File:** `pkg/ebpf/loader.go`

### Fix 6: Increase BPF map capacity (Bug #7)

Change `max_entries` from 8192 to 65536. With 3 state buckets, supports ~21K unique netns inodes.

**File:** `bpf/conntrack.c`

### Fix 7: Set informer resync period (Bug #8)

Change resync period from `0` to `5 * time.Minute` for eventual consistency.

**File:** `pkg/resolver/resolver.go`

## Verification

- `go vet ./...` — no errors
- `go test ./pkg/...` — all tests pass
- IDE diagnostics — 0 errors
