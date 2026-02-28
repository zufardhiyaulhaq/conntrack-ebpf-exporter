# Conntrack eBPF Exporter Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an eBPF-based DaemonSet that hooks conntrack insert/delete events, resolves netns to pod, and exposes per-pod Prometheus gauge metrics.

**Architecture:** kprobes on `nf_conntrack_hash_check_insert` and `nf_ct_delete` maintain per-netns counters in a BPF hash map. Go userspace reads the map on Prometheus scrape, joins with K8s informer pod data to resolve netns inode → pod, and serves metrics on `:9990/metrics`.

**Tech Stack:** BPF C with CO-RE (vmlinux.h from BTF), Go with cilium/ebpf v0.17+, client-go informer, prometheus/client_golang, logrus.

**Known limitation:** BPF counters start at 0 on startup. Existing conntrack entries are not counted. After ~120s (max TCP timeout), counters reach steady-state accuracy. This is acceptable — the goal is finding offending pods, not exact accounting.

---

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `bpf/headers/.gitkeep` (vmlinux.h generated at build time)
- Create: `.gitignore`

**Step 1: Create directory structure**

```bash
mkdir -p bpf/headers cmd pkg/ebpf pkg/resolver pkg/metrics deploy
```

**Step 2: Initialize go.mod**

Create `go.mod`:
```go
module github.com/zufardhiyaulhaq/conntrack-ebpf-exporter

go 1.23.0

// Dependencies added in subsequent tasks via go get
```

**Step 3: Create .gitignore**

Create `.gitignore`:
```
# Binaries
conntrack-ebpf-exporter
*.o
!bpf/headers/*.o

# Generated BPF (committed separately after go generate)
# pkg/ebpf/conntrack_bpf*.go and .o files ARE committed

# vmlinux.h is large — generated at build time
bpf/headers/vmlinux.h

# Go
vendor/
```

**Step 4: Commit**

```bash
git add go.mod .gitignore bpf/ cmd/ pkg/ deploy/
git commit -m "chore: scaffold project structure"
```

---

### Task 2: BPF C Program

**Files:**
- Create: `bpf/conntrack.c`

**Step 1: Write the BPF C program**

Create `bpf/conntrack.c`. This is the kernel-side eBPF program that hooks conntrack insert/delete.

```c
//go:build ignore

#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

// State buckets — must match Go constants in loader.go
#define STATE_TCP_ESTABLISHED 0
#define STATE_TCP_TIME_WAIT   1
#define STATE_TCP_CLOSE_WAIT  2
#define STATE_TCP_OTHER       3
#define STATE_UDP             4
#define STATE_OTHER           5

struct map_key {
    __u32 netns_inode;
    __u8  state;
    __u8  pad[3];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct map_key);
    __type(value, __s64);
} conntrack_counts SEC(".maps");

// Extract the state bucket from an nf_conn.
// Returns the appropriate STATE_* constant based on protocol and TCP state.
static __always_inline __u8 get_state_bucket(struct nf_conn *ct) {
    __u8 protonum;
    protonum = BPF_CORE_READ(ct, tuplehash[0].tuple.dst.protonum);

    if (protonum == IPPROTO_TCP) {
        __u8 tcp_state;
        tcp_state = BPF_CORE_READ(ct, proto.tcp.state);
        switch (tcp_state) {
        case TCP_CONNTRACK_ESTABLISHED:
            return STATE_TCP_ESTABLISHED;
        case TCP_CONNTRACK_TIME_WAIT:
            return STATE_TCP_TIME_WAIT;
        case TCP_CONNTRACK_CLOSE_WAIT:
            return STATE_TCP_CLOSE_WAIT;
        default:
            return STATE_TCP_OTHER;
        }
    }

    if (protonum == IPPROTO_UDP) {
        return STATE_UDP;
    }

    return STATE_OTHER;
}

// Extract the network namespace inode number from an nf_conn.
// Path: ct->ct_net.net->ns.inum
static __always_inline __u32 get_netns_inode(struct nf_conn *ct) {
    return BPF_CORE_READ(ct, ct_net.net, ns.inum);
}

// Increment counter for the given nf_conn's netns + state.
static __always_inline void count_insert(struct nf_conn *ct) {
    struct map_key key = {};
    key.netns_inode = get_netns_inode(ct);
    key.state = get_state_bucket(ct);

    __s64 *val = bpf_map_lookup_elem(&conntrack_counts, &key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __s64 initval = 1;
        bpf_map_update_elem(&conntrack_counts, &key, &initval, BPF_ANY);
    }
}

// Decrement counter for the given nf_conn's netns + state.
// Deletes the map entry if counter reaches 0.
static __always_inline void count_delete(struct nf_conn *ct) {
    struct map_key key = {};
    key.netns_inode = get_netns_inode(ct);
    key.state = get_state_bucket(ct);

    __s64 *val = bpf_map_lookup_elem(&conntrack_counts, &key);
    if (val) {
        __s64 new_val = __sync_fetch_and_add(val, -1) - 1;
        if (new_val <= 0) {
            bpf_map_delete_elem(&conntrack_counts, &key);
        }
    }
}

// kprobe on nf_conntrack_hash_check_insert — fires when a conntrack entry
// is being inserted into the hash table.
// Signature: int nf_conntrack_hash_check_insert(struct nf_conn *ct)
SEC("kprobe/nf_conntrack_hash_check_insert")
int BPF_KPROBE(kprobe_ct_insert, struct nf_conn *ct) {
    count_insert(ct);
    return 0;
}

// kprobe on nf_ct_delete — fires when a conntrack entry is being deleted.
// Signature: void nf_ct_delete(struct nf_conn *ct, u32 portid, int report)
SEC("kprobe/nf_ct_delete")
int BPF_KPROBE(kprobe_ct_delete, struct nf_conn *ct) {
    count_delete(ct);
    return 0;
}
```

**Step 2: Commit**

```bash
git add bpf/conntrack.c
git commit -m "feat: add BPF C program for conntrack kprobes"
```

---

### Task 3: Go BPF Loader

**Files:**
- Create: `pkg/ebpf/gen.go`
- Create: `pkg/ebpf/loader.go`

This task creates the Go-side BPF loader. The `gen.go` file contains the `go:generate` directive that invokes bpf2go. The `loader.go` file loads the compiled BPF program and provides a `ReadCounters()` method.

**Step 1: Install Go dependencies**

```bash
cd /path/to/conntrack-ebpf-exporter
go get github.com/cilium/ebpf@latest
go get github.com/cilium/ebpf/link@latest
go get github.com/cilium/ebpf/rlimit@latest
go get github.com/sirupsen/logrus@latest
```

**Step 2: Create gen.go with bpf2go directive**

Create `pkg/ebpf/gen.go`:
```go
//go:build ignore

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type map_key -target amd64 conntrack ../../bpf/conntrack.c -- -I../../bpf
```

Note: `-type map_key` generates a Go type `conntrackMapKey` matching the C struct. `-target amd64` generates only x86-64 objects. The `-I../../bpf` flag lets clang find `headers/vmlinux.h`.

**Step 3: Create loader.go**

Create `pkg/ebpf/loader.go`:
```go
//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

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

// Loader loads the BPF program and provides map access.
type Loader struct {
	objs    conntrackObjects
	kpInsert link.Link
	kpDelete link.Link
}

// NewLoader performs startup checks, loads the BPF program, and attaches kprobes.
func NewLoader() (*Loader, error) {
	// Check BTF availability
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		return nil, fmt.Errorf("BTF not available at /sys/kernel/btf/vmlinux — kernel >= 5.8 with CONFIG_DEBUG_INFO_BTF required")
	}

	// Remove memlock rlimit (required on kernels < 5.11, no-op on newer)
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	// Load BPF objects (CO-RE relocations applied automatically from kernel BTF)
	var objs conntrackObjects
	if err := loadConntrackObjects(&objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Errorf("BPF verifier error: %+v", ve)
		}
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	// Attach kprobe on nf_conntrack_hash_check_insert
	kpInsert, err := link.Kprobe("nf_conntrack_hash_check_insert", objs.KprobeCtInsert, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching kprobe nf_conntrack_hash_check_insert: %w", err)
	}

	// Attach kprobe on nf_ct_delete
	kpDelete, err := link.Kprobe("nf_ct_delete", objs.KprobeCtDelete, nil)
	if err != nil {
		kpInsert.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching kprobe nf_ct_delete: %w", err)
	}

	log.Info("BPF program loaded and kprobes attached")
	return &Loader{objs: objs, kpInsert: kpInsert, kpDelete: kpDelete}, nil
}

// ReadCounters iterates the BPF hash map and returns all {netns_inode, state} → count pairs.
func (l *Loader) ReadCounters() (map[MapKey]int64, error) {
	result := make(map[MapKey]int64)

	var bpfKey conntrackMapKey
	var value int64

	iter := l.objs.ConntrackCounts.Iterate()
	for iter.Next(&bpfKey, &value) {
		if value <= 0 {
			continue
		}
		key := MapKey{
			NetnsInode: bpfKey.NetnsInode,
			State:      bpfKey.State,
		}
		result[key] = value
	}

	if err := iter.Err(); err != nil {
		if errors.Is(err, ebpf.ErrIterationAborted) {
			log.Warn("BPF map iteration aborted (map modified during walk), partial results returned")
			return result, nil
		}
		return nil, fmt.Errorf("iterating BPF map: %w", err)
	}

	return result, nil
}

// Close detaches kprobes and closes BPF objects.
func (l *Loader) Close() error {
	var errs []error
	if l.kpInsert != nil {
		errs = append(errs, l.kpInsert.Close())
	}
	if l.kpDelete != nil {
		errs = append(errs, l.kpDelete.Close())
	}
	errs = append(errs, l.objs.Close())
	return errors.Join(errs...)
}
```

**Step 4: Run go mod tidy**

```bash
go mod tidy
```

**Step 5: Commit**

```bash
git add pkg/ebpf/gen.go pkg/ebpf/loader.go go.mod go.sum
git commit -m "feat: add Go BPF loader with kprobe attachment and map reader"
```

**Step 6: Generate BPF Go bindings (Linux only)**

This must run on Linux with clang installed. On macOS, use the Dockerfile (Task 7).

```bash
# Generate vmlinux.h from kernel BTF (run on a Linux machine or ACK node)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h

# Generate Go bindings from BPF C
cd pkg/ebpf && go generate
```

This produces `conntrack_bpfel.go` and `conntrack_bpfel.o` in `pkg/ebpf/`. Commit them:

```bash
git add pkg/ebpf/conntrack_bpfel.go pkg/ebpf/conntrack_bpfel.o
git commit -m "chore: add generated BPF Go bindings"
```

---

### Task 4: Pod Resolver (TDD)

**Files:**
- Create: `pkg/resolver/resolver.go`
- Create: `pkg/resolver/resolver_test.go`

The resolver maps netns inodes to pod metadata using K8s informer + /proc scanning.

**Step 1: Write the failing tests**

Create `pkg/resolver/resolver_test.go`:
```go
package resolver

import (
	"sync"
	"testing"
)

// mockProcReader is a test double for /proc filesystem access.
type mockProcReader struct {
	pids map[string]int    // containerID → PID
	inodes map[int]uint32  // PID → netns inode
}

func (m *mockProcReader) FindPIDForContainer(containerID string) (int, error) {
	pid, ok := m.pids[containerID]
	if !ok {
		return 0, ErrContainerNotFound
	}
	return pid, nil
}

func (m *mockProcReader) ReadNetNSInode(pid int) (uint32, error) {
	inode, ok := m.inodes[pid]
	if !ok {
		return 0, ErrNetNSNotFound
	}
	return inode, nil
}

func TestResolve_KnownPod(t *testing.T) {
	r := &PodResolver{
		cache: map[uint32]PodInfo{
			12345: {Name: "web-abc", Namespace: "default", App: "web"},
		},
		mu: sync.RWMutex{},
	}

	info, ok := r.Resolve(12345)
	if !ok {
		t.Fatal("expected pod to be found")
	}
	if info.Name != "web-abc" {
		t.Errorf("expected name web-abc, got %s", info.Name)
	}
	if info.Namespace != "default" {
		t.Errorf("expected namespace default, got %s", info.Namespace)
	}
	if info.App != "web" {
		t.Errorf("expected app web, got %s", info.App)
	}
}

func TestResolve_UnknownPod(t *testing.T) {
	r := &PodResolver{
		cache: map[uint32]PodInfo{},
		mu:    sync.RWMutex{},
	}

	_, ok := r.Resolve(99999)
	if ok {
		t.Fatal("expected pod to not be found")
	}
}

func TestAddPod(t *testing.T) {
	proc := &mockProcReader{
		pids:   map[string]int{"container-1": 100},
		inodes: map[int]uint32{100: 12345},
	}
	r := &PodResolver{
		cache: make(map[uint32]PodInfo),
		proc:  proc,
		mu:    sync.RWMutex{},
	}

	r.AddPod("web-abc", "default", "web", []string{"container-1"})

	info, ok := r.Resolve(12345)
	if !ok {
		t.Fatal("expected pod to be found after AddPod")
	}
	if info.Name != "web-abc" {
		t.Errorf("expected name web-abc, got %s", info.Name)
	}
}

func TestRemovePod(t *testing.T) {
	r := &PodResolver{
		cache: map[uint32]PodInfo{
			12345: {Name: "web-abc", Namespace: "default", App: "web"},
		},
		podInodes: map[string][]uint32{
			"default/web-abc": {12345},
		},
		mu: sync.RWMutex{},
	}

	r.RemovePod("web-abc", "default")

	_, ok := r.Resolve(12345)
	if ok {
		t.Fatal("expected pod to be removed")
	}
}
```

**Step 2: Run tests to verify they fail**

```bash
cd pkg/resolver && go test -v
```
Expected: compilation failure — types and functions don't exist yet.

**Step 3: Write the resolver implementation**

Create `pkg/resolver/resolver.go`:
```go
package resolver

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

var (
	ErrContainerNotFound = errors.New("container not found in /proc")
	ErrNetNSNotFound     = errors.New("network namespace not found")
)

// PodInfo holds the metadata needed for Prometheus labels.
type PodInfo struct {
	Name      string
	Namespace string
	App       string
}

// Resolver resolves a netns inode to pod metadata.
type Resolver interface {
	Resolve(netnsInode uint32) (PodInfo, bool)
}

// ProcReader abstracts /proc filesystem access for testability.
type ProcReader interface {
	FindPIDForContainer(containerID string) (int, error)
	ReadNetNSInode(pid int) (uint32, error)
}

// RealProcReader reads from the actual /proc filesystem.
type RealProcReader struct{}

func (r *RealProcReader) FindPIDForContainer(containerID string) (int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("reading /proc: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		cgroupPath := filepath.Join("/proc", entry.Name(), "cgroup")
		data, err := os.ReadFile(cgroupPath)
		if err != nil {
			continue
		}

		if strings.Contains(string(data), containerID) {
			return pid, nil
		}
	}

	return 0, ErrContainerNotFound
}

func (r *RealProcReader) ReadNetNSInode(pid int) (uint32, error) {
	nsPath := fmt.Sprintf("/proc/%d/ns/net", pid)
	var stat syscall.Stat_t
	if err := syscall.Stat(nsPath, &stat); err != nil {
		return 0, fmt.Errorf("stat %s: %w", nsPath, err)
	}
	return uint32(stat.Ino), nil
}

// PodResolver implements Resolver using K8s informer and /proc scanning.
type PodResolver struct {
	cache     map[uint32]PodInfo    // netns inode → pod info
	podInodes map[string][]uint32   // "namespace/name" → list of netns inodes
	proc      ProcReader
	mu        sync.RWMutex
}

// NewPodResolver creates a PodResolver and starts the K8s informer.
// nodeName is used to filter pods to the current node.
func NewPodResolver(clientset kubernetes.Interface, nodeName string, stopCh <-chan struct{}) *PodResolver {
	r := &PodResolver{
		cache:     make(map[uint32]PodInfo),
		podInodes: make(map[string][]uint32),
		proc:      &RealProcReader{},
	}

	factory := informers.NewSharedInformerFactoryWithOptions(
		clientset, 0,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = "spec.nodeName=" + nodeName
		}),
	)

	podInformer := factory.Core().V1().Pods().Informer()
	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok || pod.Status.Phase != corev1.PodRunning {
				return
			}
			r.handlePodAdd(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod, ok := newObj.(*corev1.Pod)
			if !ok {
				return
			}
			// Re-resolve on update (pod may have transitioned to Running)
			if pod.Status.Phase == corev1.PodRunning {
				r.handlePodAdd(pod)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				return
			}
			r.RemovePod(pod.Name, pod.Namespace)
		},
	})

	factory.Start(stopCh)
	factory.WaitForCacheSync(stopCh)
	log.Infof("Pod resolver started, watching pods on node %s", nodeName)

	return r
}

func (r *PodResolver) handlePodAdd(pod *corev1.Pod) {
	app := pod.Labels["app"]
	if app == "" {
		app = pod.Labels["app.kubernetes.io/name"]
	}
	if app == "" {
		app = "unknown"
	}

	var containerIDs []string
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.ContainerID != "" {
			// Format: containerd://abc123...
			parts := strings.SplitN(cs.ContainerID, "://", 2)
			if len(parts) == 2 {
				containerIDs = append(containerIDs, parts[1])
			}
		}
	}

	if len(containerIDs) == 0 {
		return
	}

	r.AddPod(pod.Name, pod.Namespace, app, containerIDs)
}

// AddPod resolves container IDs to netns inodes and caches the mapping.
func (r *PodResolver) AddPod(name, namespace, app string, containerIDs []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	podKey := namespace + "/" + name
	info := PodInfo{Name: name, Namespace: namespace, App: app}

	for _, cid := range containerIDs {
		pid, err := r.proc.FindPIDForContainer(cid)
		if err != nil {
			log.Debugf("Could not find PID for container %s (pod %s): %v", cid[:12], name, err)
			continue
		}

		inode, err := r.proc.ReadNetNSInode(pid)
		if err != nil {
			log.Debugf("Could not read netns inode for PID %d (pod %s): %v", pid, name, err)
			continue
		}

		r.cache[inode] = info
		r.podInodes[podKey] = append(r.podInodes[podKey], inode)
		log.Debugf("Resolved pod %s/%s → netns inode %d", namespace, name, inode)
		return // All containers in a pod share the same netns, one is enough
	}
}

// RemovePod removes all netns inode mappings for the given pod.
func (r *PodResolver) RemovePod(name, namespace string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	podKey := namespace + "/" + name
	inodes, ok := r.podInodes[podKey]
	if !ok {
		return
	}

	for _, inode := range inodes {
		delete(r.cache, inode)
	}
	delete(r.podInodes, podKey)
	log.Debugf("Removed pod %s/%s from resolver", namespace, name)
}

// Resolve looks up pod metadata by netns inode.
func (r *PodResolver) Resolve(netnsInode uint32) (PodInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	info, ok := r.cache[netnsInode]
	return info, ok
}
```

Note: You need to add the `metav1` import. Run:
```bash
go get k8s.io/apimachinery@latest
go get k8s.io/client-go@latest
```

Add this import to resolver.go:
```go
import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	// ... other imports
)
```

**Step 4: Run tests to verify they pass**

```bash
cd pkg/resolver && go test -v
```
Expected: all 4 tests pass.

**Step 5: Commit**

```bash
git add pkg/resolver/resolver.go pkg/resolver/resolver_test.go go.mod go.sum
git commit -m "feat: add pod resolver with K8s informer and /proc scanning"
```

---

### Task 5: Prometheus Metrics Collector (TDD)

**Files:**
- Create: `pkg/metrics/collector.go`
- Create: `pkg/metrics/collector_test.go`

**Step 1: Write the failing tests**

Create `pkg/metrics/collector_test.go`:
```go
package metrics

import (
	"testing"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/client_golang/prometheus"
)

type mockMapReader struct {
	counters map[ebpfpkg.MapKey]int64
	err      error
}

func (m *mockMapReader) ReadCounters() (map[ebpfpkg.MapKey]int64, error) {
	return m.counters, m.err
}

func (m *mockMapReader) Close() error { return nil }

type mockResolver struct {
	pods map[uint32]resolver.PodInfo
}

func (m *mockResolver) Resolve(netnsInode uint32) (resolver.PodInfo, bool) {
	info, ok := m.pods[netnsInode]
	return info, ok
}

func collectMetrics(c prometheus.Collector) []*dto.MetricFamily {
	ch := make(chan prometheus.Metric, 100)
	go func() {
		c.Collect(ch)
		close(ch)
	}()

	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}

	// Convert to MetricFamily for inspection
	reg := prometheus.NewRegistry()
	reg.MustRegister(c)
	families, _ := reg.Gather()
	return families
}

func TestCollector_EmitsMetricsForKnownPod(t *testing.T) {
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{
			{NetnsInode: 100, State: ebpfpkg.StateTCPEstablished}: 42,
			{NetnsInode: 100, State: ebpfpkg.StateUDP}:            15,
		},
	}
	res := &mockResolver{
		pods: map[uint32]resolver.PodInfo{
			100: {Name: "web-abc", Namespace: "default", App: "web"},
		},
	}

	c := NewCollector(reader, res)
	families := collectMetrics(c)

	if len(families) == 0 {
		t.Fatal("expected at least one metric family")
	}

	family := families[0]
	if *family.Name != "node_conntrack_ebpf_entries_by_pod" {
		t.Errorf("unexpected metric name: %s", *family.Name)
	}
	if len(family.Metric) != 2 {
		t.Errorf("expected 2 metrics, got %d", len(family.Metric))
	}
}

func TestCollector_UnresolvedNetnsGetsUnknownLabels(t *testing.T) {
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{
			{NetnsInode: 999, State: ebpfpkg.StateUDP}: 10,
		},
	}
	res := &mockResolver{pods: map[uint32]resolver.PodInfo{}}

	c := NewCollector(reader, res)
	families := collectMetrics(c)

	if len(families) == 0 {
		t.Fatal("expected metric family")
	}

	metric := families[0].Metric[0]
	for _, label := range metric.Label {
		if *label.Name == "pod" && *label.Value != "unknown" {
			t.Errorf("expected pod=unknown for unresolved netns, got %s", *label.Value)
		}
	}
}

func TestCollector_SkipsZeroCountEntries(t *testing.T) {
	reader := &mockMapReader{
		counters: map[ebpfpkg.MapKey]int64{}, // empty — no entries
	}
	res := &mockResolver{pods: map[uint32]resolver.PodInfo{}}

	c := NewCollector(reader, res)
	families := collectMetrics(c)

	if len(families) != 0 {
		for _, f := range families {
			if len(f.Metric) > 0 {
				t.Errorf("expected no metrics for empty counters, got %d", len(f.Metric))
			}
		}
	}
}
```

**Step 2: Run tests to verify they fail**

```bash
cd pkg/metrics && go test -v
```
Expected: compilation failure.

**Step 3: Write the collector implementation**

Create `pkg/metrics/collector.go`:
```go
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"
)

const (
	metricName = "node_conntrack_ebpf_entries_by_pod"
	metricHelp = "Number of conntrack entries per pod, broken down by connection state."
)

var desc = prometheus.NewDesc(
	metricName,
	metricHelp,
	[]string{"pod", "namespace", "app", "state"},
	nil,
)

// Collector implements prometheus.Collector for per-pod conntrack metrics.
type Collector struct {
	reader   ebpfpkg.MapReader
	resolver resolver.Resolver
}

// NewCollector creates a new Collector.
func NewCollector(reader ebpfpkg.MapReader, resolver resolver.Resolver) *Collector {
	return &Collector{reader: reader, resolver: resolver}
}

// Describe sends the metric descriptor.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- desc
}

// Collect reads BPF counters, resolves pods, and emits metrics.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	counters, err := c.reader.ReadCounters()
	if err != nil {
		log.Errorf("Failed to read BPF counters: %v", err)
		return
	}

	for key, count := range counters {
		if count <= 0 {
			continue
		}

		podName := "unknown"
		namespace := "unknown"
		app := "unknown"

		info, ok := c.resolver.Resolve(key.NetnsInode)
		if ok {
			podName = info.Name
			namespace = info.Namespace
			app = info.App
		}

		stateName, ok := ebpfpkg.StateNames[key.State]
		if !ok {
			stateName = "other"
		}

		metric, err := prometheus.NewConstMetric(
			desc,
			prometheus.GaugeValue,
			float64(count),
			podName, namespace, app, stateName,
		)
		if err != nil {
			log.Errorf("Failed to create metric: %v", err)
			continue
		}

		ch <- metric
	}
}
```

**Step 4: Install test dependency and run tests**

```bash
go get github.com/prometheus/client_golang@latest
go get github.com/prometheus/client_model@latest
go mod tidy
cd pkg/metrics && go test -v
```
Expected: all 3 tests pass.

**Step 5: Commit**

```bash
git add pkg/metrics/collector.go pkg/metrics/collector_test.go go.mod go.sum
git commit -m "feat: add Prometheus collector with per-pod conntrack metrics"
```

---

### Task 6: Entry Point

**Files:**
- Create: `cmd/main.go`

**Step 1: Write the main entry point**

Create `cmd/main.go`:
```go
//go:build linux

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/metrics"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"
)

func main() {
	// Configure logging
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("Invalid log level %q: %v", logLevel, err)
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	// Read config
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Fatal("NODE_NAME environment variable is required (set via downward API)")
	}
	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		metricsPort = "9990"
	}

	log.Infof("Starting conntrack-ebpf-exporter on node %s", nodeName)

	// Load BPF program and attach kprobes
	loader, err := ebpfpkg.NewLoader()
	if err != nil {
		log.Fatalf("Failed to load BPF program: %v", err)
	}
	defer loader.Close()

	// Create K8s client (in-cluster config)
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to get in-cluster config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create K8s client: %v", err)
	}

	// Start pod resolver
	stopCh := make(chan struct{})
	podResolver := resolver.NewPodResolver(clientset, nodeName, stopCh)

	// Register Prometheus collector
	collector := metrics.NewCollector(loader, podResolver)
	prometheus.MustRegister(collector)

	// Start HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	addr := ":" + metricsPort
	server := &http.Server{Addr: addr, Handler: mux}

	go func() {
		log.Infof("Serving metrics on %s/metrics", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for SIGTERM/SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	log.Infof("Received signal %v, shutting down", sig)

	close(stopCh)
	server.Shutdown(context.Background())
	log.Info("Shutdown complete")
}
```

**Step 2: Verify compilation (on Linux or with build tag awareness)**

```bash
GOOS=linux go build ./cmd/
```

Note: This will fail if BPF generated files aren't present yet. That's expected — Task 3 Step 6 generates them.

**Step 3: Commit**

```bash
git add cmd/main.go
git commit -m "feat: add main entry point with signal handling and HTTP server"
```

---

### Task 7: Build System

**Files:**
- Create: `Makefile`
- Create: `Dockerfile`

**Step 1: Create Makefile**

Create `Makefile`:
```makefile
BINARY_NAME := conntrack-ebpf-exporter
IMAGE_NAME := conntrack-ebpf-exporter
IMAGE_TAG := latest

.PHONY: all generate build docker clean

all: generate build

## generate: Generate vmlinux.h and BPF Go bindings (Linux only, requires clang + bpftool)
generate:
	@echo "==> Generating vmlinux.h from kernel BTF..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h
	@echo "==> Generating BPF Go bindings..."
	cd pkg/ebpf && go generate

## build: Build the Go binary (Linux amd64)
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd/

## docker: Build the Docker image (generates BPF inside container)
docker:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f pkg/ebpf/conntrack_bpfel.go pkg/ebpf/conntrack_bpfel.o
	rm -f bpf/headers/vmlinux.h

## test: Run Go tests
test:
	go test ./pkg/...

## lint: Run linter
lint:
	golangci-lint run ./...
```

**Step 2: Create Dockerfile**

Create `Dockerfile`:
```dockerfile
# Stage 1: Generate BPF objects and build Go binary
FROM golang:1.23-bookworm AS builder

# Install BPF build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy go module files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Generate vmlinux.h from the build environment's BTF (if available)
# For cross-compilation, a pre-generated vmlinux.h should be in bpf/headers/
RUN if [ -f /sys/kernel/btf/vmlinux ]; then \
        bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/headers/vmlinux.h; \
    fi

# Generate BPF Go bindings
RUN cd pkg/ebpf && go generate

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o conntrack-ebpf-exporter ./cmd/

# Stage 2: Minimal runtime image
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/conntrack-ebpf-exporter /conntrack-ebpf-exporter

ENTRYPOINT ["/conntrack-ebpf-exporter"]
```

**Step 3: Commit**

```bash
git add Makefile Dockerfile
git commit -m "feat: add Makefile and multi-stage Dockerfile"
```

---

### Task 8: Kubernetes Deployment

**Files:**
- Create: `deploy/daemonset.yaml`

**Step 1: Create the deployment manifest**

Create `deploy/daemonset.yaml`:
```yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: conntrack-ebpf-exporter
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: conntrack-ebpf-exporter
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: conntrack-ebpf-exporter
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: conntrack-ebpf-exporter
subjects:
  - kind: ServiceAccount
    name: conntrack-ebpf-exporter
    namespace: monitoring
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: conntrack-ebpf-exporter
  namespace: monitoring
  labels:
    app: conntrack-ebpf-exporter
spec:
  selector:
    matchLabels:
      app: conntrack-ebpf-exporter
  template:
    metadata:
      labels:
        app: conntrack-ebpf-exporter
      annotations:
        sidecar.istio.io/inject: "false"
    spec:
      serviceAccountName: conntrack-ebpf-exporter
      hostNetwork: true
      hostPID: true
      containers:
        - name: exporter
          image: conntrack-ebpf-exporter:latest
          securityContext:
            privileged: true
          env:
            - name: NODE_NAME
              valueFrom:
                fieldRef:
                  fieldPath: spec.nodeName
            - name: METRICS_PORT
              value: "9990"
            - name: LOG_LEVEL
              value: "info"
          ports:
            - name: metrics
              containerPort: 9990
              protocol: TCP
          livenessProbe:
            httpGet:
              path: /healthz
              port: 9990
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /healthz
              port: 9990
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 100m
              memory: 128Mi
      tolerations:
        - operator: Exists
---
apiVersion: operator.victoriametrics.com/v1beta1
kind: VMServiceScrape
metadata:
  name: conntrack-ebpf-exporter
  namespace: monitoring
spec:
  selector:
    matchLabels:
      app: conntrack-ebpf-exporter
  endpoints:
    - port: "9990"
      interval: 30s
      path: /metrics
```

**Step 2: Commit**

```bash
git add deploy/daemonset.yaml
git commit -m "feat: add DaemonSet, RBAC, and VMServiceScrape manifests"
```

---

## Verification Checklist

After all tasks are complete, verify on a Linux machine or AliCloud ACK node:

1. **BPF generation:** `make generate` succeeds, `pkg/ebpf/conntrack_bpfel.go` exists
2. **Unit tests:** `make test` passes all resolver and collector tests
3. **Binary builds:** `make build` produces `conntrack-ebpf-exporter` binary
4. **Docker builds:** `make docker` succeeds
5. **Deploy and test on ACK node:**
   - `kubectl apply -f deploy/daemonset.yaml`
   - `curl <node-ip>:9990/metrics | grep node_conntrack_ebpf`
   - Verify per-pod labels appear for running pods
   - Verify UDP and TCP state breakdowns
   - Compare `sum(node_conntrack_ebpf_entries_by_pod)` vs `node_nf_conntrack_entries`
