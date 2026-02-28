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

// Loader loads the BPF program and provides map access.
type Loader struct {
	objs     conntrackObjects
	kpInsert link.Link
	kpDelete link.Link
}

// NewLoader performs startup checks, loads the BPF program, and attaches kprobes.
func NewLoader() (*Loader, error) {
	// Check BTF availability
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		return nil, fmt.Errorf("BTF not available at /sys/kernel/btf/vmlinux — kernel >= 5.8 with CONFIG_DEBUG_INFO_BTF required")
	}

	// Remove memlock rlimit (required on kernels < 5.11, no-op on newer).
	// Non-fatal: some container runtimes block setrlimit even in privileged mode,
	// and kernels >= 5.11 (or backported 5.10) use cgroup-based memlock accounting.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warnf("Could not remove memlock rlimit (may be fine on kernel >= 5.11): %v", err)
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
