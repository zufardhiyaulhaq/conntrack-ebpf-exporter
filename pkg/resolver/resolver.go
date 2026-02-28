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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	cache     map[uint32]PodInfo  // netns inode → pod info
	podInodes map[string][]uint32 // "namespace/name" → list of netns inodes
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
			if pod.Status.Phase == corev1.PodRunning {
				r.handlePodAdd(pod)
			}
		},
		DeleteFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
				if !ok {
					return
				}
				pod, ok = tombstone.Obj.(*corev1.Pod)
				if !ok {
					return
				}
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

	// Skip if already resolved — prevents duplicate entries from repeated update events
	if _, exists := r.podInodes[podKey]; exists {
		return
	}

	info := PodInfo{Name: name, Namespace: namespace, App: app}

	for _, cid := range containerIDs {
		pid, err := r.proc.FindPIDForContainer(cid)
		if err != nil {
			log.Debugf("Could not find PID for container %s (pod %s): %v", cid, name, err)
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
