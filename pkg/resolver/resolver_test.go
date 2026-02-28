package resolver

import (
	"sync"
	"testing"
)

// mockProcReader is a test double for /proc filesystem access.
type mockProcReader struct {
	pids   map[string]int   // containerID → PID
	inodes map[int]uint32   // PID → netns inode
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
		ipCache:   make(map[string]PodInfo),
		podInodes: make(map[string][]uint32),
		podIPs:    make(map[string][]string),
		mu:        sync.RWMutex{},
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
		cache:     map[uint32]PodInfo{},
		ipCache:   make(map[string]PodInfo),
		podInodes: make(map[string][]uint32),
		podIPs:    make(map[string][]string),
		mu:        sync.RWMutex{},
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
		cache:     make(map[uint32]PodInfo),
		ipCache:   make(map[string]PodInfo),
		podInodes: make(map[string][]uint32),
		podIPs:    make(map[string][]string),
		proc:      proc,
		mu:        sync.RWMutex{},
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
		ipCache: map[string]PodInfo{
			"10.0.1.5": {Name: "web-abc", Namespace: "default", App: "web"},
		},
		podInodes: map[string][]uint32{
			"default/web-abc": {12345},
		},
		podIPs: map[string][]string{
			"default/web-abc": {"10.0.1.5"},
		},
		mu: sync.RWMutex{},
	}

	r.RemovePod("web-abc", "default")

	_, ok := r.Resolve(12345)
	if ok {
		t.Fatal("expected pod to be removed from inode cache")
	}
	_, ok = r.ResolveByIP("10.0.1.5")
	if ok {
		t.Fatal("expected pod to be removed from IP cache")
	}
}

func TestResolveByIP(t *testing.T) {
	r := &PodResolver{
		cache:   make(map[uint32]PodInfo),
		ipCache: map[string]PodInfo{
			"10.0.1.5": {Name: "web-abc", Namespace: "default", App: "web"},
		},
		podInodes: make(map[string][]uint32),
		podIPs:    make(map[string][]string),
		mu:        sync.RWMutex{},
	}

	info, ok := r.ResolveByIP("10.0.1.5")
	if !ok {
		t.Fatal("expected pod to be found by IP")
	}
	if info.Name != "web-abc" {
		t.Errorf("expected name web-abc, got %s", info.Name)
	}

	_, ok = r.ResolveByIP("10.0.99.99")
	if ok {
		t.Fatal("expected unknown IP to not resolve")
	}
}

func TestAddPodIP_RecycledIPCleansUpOldPod(t *testing.T) {
	r := &PodResolver{
		cache: make(map[uint32]PodInfo),
		ipCache: map[string]PodInfo{
			"10.0.1.5": {Name: "old-pod", Namespace: "default", App: "old"},
		},
		podInodes: make(map[string][]uint32),
		podIPs: map[string][]string{
			"default/old-pod": {"10.0.1.5"},
		},
		mu: sync.RWMutex{},
	}

	// New pod gets the same IP (recycled)
	r.AddPodIP("new-pod", "default", "new", "10.0.1.5")

	// IP should now resolve to new pod
	info, ok := r.ResolveByIP("10.0.1.5")
	if !ok {
		t.Fatal("expected IP to resolve")
	}
	if info.Name != "new-pod" {
		t.Errorf("expected new-pod, got %s", info.Name)
	}

	// Old pod's IP list should be cleaned up
	if ips := r.podIPs["default/old-pod"]; len(ips) != 0 {
		t.Errorf("expected old pod IP list to be empty, got %v", ips)
	}
}

func TestRemovePod_DoesNotDeleteRecycledIP(t *testing.T) {
	r := &PodResolver{
		cache: make(map[uint32]PodInfo),
		ipCache: map[string]PodInfo{
			// IP was recycled: ipCache points to new-pod
			"10.0.1.5": {Name: "new-pod", Namespace: "default", App: "new"},
		},
		podInodes: make(map[string][]uint32),
		podIPs: map[string][]string{
			// But old-pod's list still references the IP (stale)
			"default/old-pod": {"10.0.1.5"},
		},
		mu: sync.RWMutex{},
	}

	// Removing old-pod should NOT delete the IP mapping (it belongs to new-pod now)
	r.RemovePod("old-pod", "default")

	info, ok := r.ResolveByIP("10.0.1.5")
	if !ok {
		t.Fatal("expected IP to still resolve after removing old pod")
	}
	if info.Name != "new-pod" {
		t.Errorf("expected new-pod, got %s", info.Name)
	}
}
