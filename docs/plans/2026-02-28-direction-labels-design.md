# Direction Labels + Node IP Detection Design

## Context

After the bugfix pass, Cilium CT metrics show a large number of "unknown" entries because:
1. The exporter only attributes connections by **source IP** — inbound connections to local pods show the remote IP (unresolvable) as the source
2. The node's own traffic (kubelet, kube-proxy, systemd services) uses the node IP which isn't in the pod resolver

This design adds bidirectional attribution (source + destination) and node IP detection to both the kernel conntrack and Cilium CT collectors.

## Goal

For every connection tracked, identify both endpoints:
- Which pod initiated it (direction=source)
- Which pod received it (direction=destination)

Also identify the node itself as a known entity instead of "unknown".

## Architecture

Both data sources (kernel conntrack BPF map and Cilium CT maps) contain source and destination IPs for every connection. The change:

1. **BPF program**: Switch from netns-inode-based counting to IP-based counting with direction. Each connection produces 2 map entries (one for source IP, one for destination IP).
2. **Cilium reader**: Already has both IPs in the CT tuple. Emit two count keys per entry instead of one.
3. **Both collectors**: Add a `direction` label (`source` or `destination`) to the Prometheus metric.
4. **Resolver**: Register the node's IP. When resolving, return `{Name: "node", Namespace: "kube-system", App: <node-name>}` for the node IP.

### Example output

```
# Pod web-abc making outbound TCP connections
node_conntrack_ebpf_entries_by_pod{pod="web-abc", namespace="default", app="web", protocol="tcp", direction="source"} 150

# Pod api-xyz receiving inbound TCP connections
node_conntrack_ebpf_entries_by_pod{pod="api-xyz", namespace="default", app="api", protocol="tcp", direction="destination"} 300

# Node itself making outbound UDP connections (likely DNS)
node_cilium_ct_entries_by_pod{pod="node", namespace="kube-system", app="node-abc", protocol="udp", direction="source"} 8000

# External traffic to local pod (source is unknown, destination is known)
node_cilium_ct_entries_by_pod{pod="unknown", namespace="unknown", app="unknown", protocol="tcp", direction="source"} 50
node_cilium_ct_entries_by_pod{pod="web-abc", namespace="default", app="web", protocol="tcp", direction="destination"} 50
```

## Detailed Changes

### 1. BPF Program (`bpf/conntrack.c`)

**Map key structure change:**
```c
// Before:
struct map_key {
    __u32 netns_inode;
    __u8  proto;
    __u8  pad[3];
};

// After:
struct map_key {
    __u32 ip;         // IPv4 address in network byte order
    __u8  proto;      // 0=tcp, 1=udp, 2=other
    __u8  direction;  // 0=source, 1=destination
    __u8  pad[2];
};
```

**count_insert** reads source and destination IPs from `nf_conn.tuplehash[0].tuple`:
- `src_ip = BPF_CORE_READ(ct, tuplehash[0].tuple.src.u3.ip)`
- `dst_ip = BPF_CORE_READ(ct, tuplehash[0].tuple.dst.u3.ip)`
- Emit two map entries: `{src_ip, proto, 0}++` and `{dst_ip, proto, 1}++`

**count_delete** does the same but decrements.

**get_proto_bucket** stays the same (reads protocol from tuple).

### 2. Go Types (`pkg/ebpf/types.go`)

```go
const (
    DirectionSource uint8 = 0
    DirectionDest   uint8 = 1
)

var DirectionNames = map[uint8]string{
    DirectionSource: "source",
    DirectionDest:   "destination",
}

type MapKey struct {
    IP        uint32
    Proto     uint8
    Direction uint8
    Pad       [2]uint8
}
```

### 3. Kernel Conntrack Loader (`pkg/ebpf/loader.go`)

`ReadCounters()` converts `key.IP` (uint32) to a string IP for the return value. The return type stays `map[MapKey]int64` since the collector needs the raw key for direction lookup.

### 4. Cilium Types (`pkg/ebpf/cilium_types.go`)

```go
type CiliumCountKey struct {
    IP        string // source or destination IP
    Protocol  string // "tcp", "udp", "other"
    Direction string // "source" or "destination"
}
```

### 5. Cilium Reader (`pkg/ebpf/cilium.go`)

In `iterateMap`, for each original-direction CT entry, emit TWO count keys:
- `{IP: sourceAddr, Protocol: proto, Direction: "source"}`
- `{IP: destAddr, Protocol: proto, Direction: "destination"}`

### 6. Kernel Conntrack Collector (`pkg/metrics/collector.go`)

- Convert `key.IP` (uint32) to string IP
- Use `resolver.ResolveByIP(ip)` instead of `resolver.Resolve(netnsInode)`
- Add `"direction"` to metric label list
- Look up direction name from `DirectionNames[key.Direction]`

### 7. Cilium Collector (`pkg/metrics/cilium_collector.go`)

- Add `"direction"` to metric label list
- Include `key.Direction` in the `ciliumMetricKey` aggregation struct

### 8. Resolver (`pkg/resolver/resolver.go`)

Add node IP detection:

```go
func (r *PodResolver) SetNodeInfo(nodeIP, nodeName string) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.ipCache[nodeIP] = PodInfo{Name: "node", Namespace: "kube-system", App: nodeName}
}
```

### 9. Main (`cmd/main.go`)

```go
nodeIP := os.Getenv("NODE_IP")
if nodeIP != "" {
    podResolver.SetNodeInfo(nodeIP, nodeName)
}
```

### 10. DaemonSet (`deploy/daemonset.yaml`)

```yaml
- name: NODE_IP
  valueFrom:
    fieldRef:
      fieldPath: status.hostIP
```

## Test Changes

- `pkg/metrics/collector_test.go` — Update MapKey to use IP+Direction, test direction label, test aggregation with direction
- `pkg/metrics/cilium_collector_test.go` — Update CiliumCountKey to include Direction, test direction label
- `pkg/resolver/resolver_test.go` — Add test for SetNodeInfo

## Verification

- `go vet ./...` — no errors
- `go test ./pkg/... -v` — all tests pass
- IDE diagnostics — 0 errors
