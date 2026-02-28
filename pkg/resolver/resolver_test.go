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
		cache:     make(map[uint32]PodInfo),
		podInodes: make(map[string][]uint32),
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
