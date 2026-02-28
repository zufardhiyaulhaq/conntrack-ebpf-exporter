# Conntrack eBPF Exporter — Design

## Problem

AliCloud ACK nodes show conntrack spikes from 10K to 500K. No existing metric provides per-pod conntrack visibility. StatsD UDP traffic from OTel Collector DaemonSets is suspected — each packet creates a conntrack entry held for 30s.

## Solution

A DaemonSet that hooks kernel conntrack events via eBPF kprobes, resolves network namespace to pod, and exposes per-pod Prometheus gauge metrics.

## Architecture

```
Kernel:
  kprobe/nf_conntrack_hash_check_insert → increment counter
  kprobe/nf_ct_delete                   → decrement counter
  BPF_MAP_TYPE_HASH: {netns_inode, state_bucket} → s64 counter

Userspace (Go):
  cilium/ebpf reads BPF map on scrape
  K8s informer + /proc scan resolves netns inode → pod
  Prometheus custom collector exposes per-pod gauge
```

## Target Environment

- Kernel: 5.10.134-19.1.1.lifsea8.x86_64 (AliCloud ACK)
- BTF: available at /sys/kernel/btf/vmlinux
- CO-RE: yes
- CNI: Terway

## BPF Program (`bpf/conntrack.c`)

### kprobes

- `kprobe/nf_conntrack_hash_check_insert` — fires on new conntrack entry insertion
- `kprobe/nf_ct_delete` — fires on conntrack entry removal

### Probe Logic

1. Read `nf_conn *ct` from function argument
2. Extract netns inode: `BPF_CORE_READ(ct, ct_net, ns.inum)`
3. Extract protocol: `ct->tuplehash[0].tuple.dst.protonum` (TCP=6, UDP=17)
4. For TCP, read state from `ct->proto.tcp.state` and bucket:
   - ESTABLISHED → `TCP_ESTABLISHED`
   - TIME_WAIT → `TCP_TIME_WAIT`
   - CLOSE_WAIT → `TCP_CLOSE_WAIT`
   - All other TCP → `TCP_OTHER`
5. UDP → `UDP`, everything else → `OTHER`
6. Build map key `{netns_inode, state_bucket}`
7. Insert probe: atomic increment counter
8. Delete probe: atomic decrement, delete map entry if counter reaches 0

### BPF Map

```c
struct map_key {
    u32 netns_inode;
    u8  state;  // TCP_ESTABLISHED=0, TCP_TIME_WAIT=1, TCP_CLOSE_WAIT=2, TCP_OTHER=3, UDP=4, OTHER=5
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct map_key);
    __type(value, s64);
} conntrack_counts SEC(".maps");
```

Max entries: 8192 (300 pods x 6 states = 1,800 + headroom).

## Go Userspace

### BPF Loader (`pkg/ebpf/loader.go`)

**Startup checks:**
1. Verify `/sys/kernel/btf/vmlinux` exists
2. Verify BPF capabilities (`CAP_BPF`, `CAP_NET_ADMIN`)
3. Load BPF object via `cilium/ebpf` with CO-RE
4. Attach kprobes

**Map reading:**
- `ReadCounters() map[MapKey]int64` — iterates BPF hash map
- Called by Prometheus collector on each scrape

### Pod Resolver (`pkg/resolver/resolver.go`)

**Mapping netns inode to pod:**
1. K8s informer watches Pods with field selector `spec.nodeName=<NODE_NAME>`
2. On pod Add: find container PID via `/proc/<pid>/cgroup` matching container ID, then `stat /proc/<pid>/ns/net` for netns inode
3. Store: `netns_inode → {pod_name, namespace, app_label}`
4. On pod Delete: remove mapping
5. Protected by `sync.RWMutex`
6. Unresolved netns inodes labeled `unknown`

### Metrics Collector (`pkg/metrics/collector.go`)

Implements `prometheus.Collector` (custom collector).

**On Collect():**
1. `loader.ReadCounters()` → `{netns_inode, state} → count`
2. `resolver.Resolve(netns_inode)` → `{pod, namespace, app}`
3. Emit gauge: `node_conntrack_ebpf_entries_by_pod{pod, namespace, app, state}`
4. Skip entries with count <= 0

**Labels:**

| Label | Source |
|-------|--------|
| pod | K8s pod name |
| namespace | K8s namespace |
| app | `app` or `app.kubernetes.io/name` label |
| state | tcp_established, tcp_time_wait, tcp_close_wait, tcp_other, udp, other |

**Cardinality:** ~300 pods x 3-4 active states = ~900-1,200 series per node.

### Entry Point (`cmd/main.go`)

1. Parse config from environment
2. Run startup checks (BTF, capabilities)
3. Load BPF program, attach kprobes
4. Start pod resolver (K8s informer)
5. Register Prometheus collector
6. Start HTTP server `:9990/metrics`
7. Handle SIGTERM (detach kprobes, close BPF objects)

**Environment variables:**
- `NODE_NAME` — from downward API
- `METRICS_PORT` — default `9990`
- `LOG_LEVEL` — default `info`

## Deployment (`deploy/daemonset.yaml`)

- DaemonSet: `hostNetwork: true`, `hostPID: true`, `privileged: true`
- NODE_NAME from downward API
- RBAC: get/list/watch Pods
- Istio sidecar injection disabled
- Resources: 100m CPU, 128Mi memory
- VMServiceScrape: 30s scrape interval

## Project Structure

```
conntrack-ebpf-exporter/
├── bpf/conntrack.c
├── cmd/main.go
├── pkg/ebpf/loader.go
├── pkg/resolver/resolver.go
├── pkg/metrics/collector.go
├── deploy/daemonset.yaml
├── Dockerfile
├── Makefile
└── go.mod
```

## Tech Stack

- BPF: C with CO-RE (vmlinux.h from BTF)
- Go: cilium/ebpf, client-go, prometheus/client_golang, logrus
- Module: github.com/zufardhiyaulhaq/conntrack-ebpf-exporter

## Decisions

1. Event-driven BPF counters (not periodic scan) — lowest overhead
2. BPF-side cleanup when counter hits 0 — keeps map small
3. K8s informer watch for pod resolution — real-time, minimal API load
4. Custom Prometheus collector — dynamic labels, no pre-registration
5. CO-RE with BTF — portable, no per-kernel compilation
6. Startup checks fail fast with clear errors
7. Source-pod only metrics, no destination — controls cardinality
