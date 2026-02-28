//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"
)

const (
	bpfSourcePath = "/bpf/conntrack.c"
	vmlinuxPath   = "/tmp/vmlinux.h"
	compiledPath  = "/tmp/conntrack.o"
)

// Loader compiles the BPF program at runtime, loads it, and provides map access.
type Loader struct {
	coll     *ebpf.Collection
	kpInsert link.Link
	kpDelete link.Link
}

// NewLoader generates vmlinux.h from the running kernel's BTF, compiles the
// BPF C source with clang, loads the resulting object, and attaches kprobes.
func NewLoader() (*Loader, error) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		return nil, fmt.Errorf("BTF not available at /sys/kernel/btf/vmlinux — kernel >= 5.8 with CONFIG_DEBUG_INFO_BTF required")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Warnf("Could not remove memlock rlimit (may be fine on kernel >= 5.11): %v", err)
	}

	// Generate vmlinux.h from the running kernel's BTF
	log.Info("Generating vmlinux.h from kernel BTF...")
	vmlinuxFile, err := os.Create(vmlinuxPath)
	if err != nil {
		return nil, fmt.Errorf("creating vmlinux.h: %w", err)
	}
	cmd := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c")
	cmd.Stdout = vmlinuxFile
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		vmlinuxFile.Close()
		return nil, fmt.Errorf("generating vmlinux.h: %w", err)
	}
	vmlinuxFile.Close()
	log.Info("vmlinux.h generated")

	// Compile BPF program against the kernel-matched vmlinux.h
	log.Info("Compiling BPF program...")
	targetArch := "x86"
	switch runtime.GOARCH {
	case "arm64":
		targetArch = "arm64"
	case "s390x":
		targetArch = "s390"
	case "ppc64le":
		targetArch = "powerpc"
	}
	cmd = exec.Command("clang",
		"-O2", "-g",
		"-target", "bpf",
		"-D__TARGET_ARCH_"+targetArch,
		"-I/tmp",         // vmlinux.h
		"-I/usr/include", // bpf/bpf_helpers.h etc.
		"-c", bpfSourcePath,
		"-o", compiledPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("compiling BPF program: %w", err)
	}
	log.Info("BPF program compiled")

	// Load compiled BPF object
	spec, err := ebpf.LoadCollectionSpec(compiledPath)
	if err != nil {
		return nil, fmt.Errorf("loading BPF collection spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Errorf("BPF verifier error: %+v", ve)
		}
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	// Attach kprobes
	kpInsert, err := link.Kprobe("nf_conntrack_hash_check_insert", coll.Programs["kprobe_ct_insert"], nil)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("attaching kprobe nf_conntrack_hash_check_insert: %w", err)
	}

	kpDelete, err := link.Kprobe("nf_ct_delete", coll.Programs["kprobe_ct_delete"], nil)
	if err != nil {
		kpInsert.Close()
		coll.Close()
		return nil, fmt.Errorf("attaching kprobe nf_ct_delete: %w", err)
	}

	log.Info("BPF program loaded and kprobes attached")
	return &Loader{coll: coll, kpInsert: kpInsert, kpDelete: kpDelete}, nil
}

// ReadCounters iterates the BPF hash map and returns all {ip, proto, direction} → count pairs.
func (l *Loader) ReadCounters() (map[MapKey]int64, error) {
	result := make(map[MapKey]int64)

	m := l.coll.Maps["conntrack_counts"]
	if m == nil {
		return nil, fmt.Errorf("BPF map 'conntrack_counts' not found")
	}

	var key MapKey
	var value int64

	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if value <= 0 {
			continue
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
	if l.coll != nil {
		l.coll.Close()
	}
	return errors.Join(errs...)
}
