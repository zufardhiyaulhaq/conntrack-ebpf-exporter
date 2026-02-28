//go:build linux

package ebpf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
)

const (
	ciliumIterSourcePath   = "/bpf/cilium_iter.c"
	ciliumIterCompiledPath = "/tmp/cilium_iter.o"
	ciliumIterMapName      = "cilium_iter_counts"
)

// CiliumIterReader uses a BPF iterator to aggregate Cilium's CT map entries
// entirely in kernel space. The kernel walks the map and writes aggregated
// counts into a small output map that Go reads after each scrape.
type CiliumIterReader struct {
	coll       *ebpf.Collection
	ct4Iter    *link.Iter
	any4Iter   *link.Iter // nil if cilium_ct_any4_ not present
	outputMap  *ebpf.Map
	ct4ExtMap  *ebpf.Map // external Cilium map (close on teardown)
	any4ExtMap *ebpf.Map // external Cilium map (close on teardown)
}

// NewCiliumIterReader compiles the BPF iterator program, attaches it to
// Cilium's CT maps, and returns a reader that satisfies CiliumReader.
// Returns an error if Cilium maps are not found or BPF iterators are
// unsupported (kernel < 5.9).
func NewCiliumIterReader() (*CiliumIterReader, error) {
	// Find Cilium's external CT maps.
	ct4Map, err := findBPFMapByName(ciliumCT4MapName)
	if err != nil {
		return nil, fmt.Errorf("cilium CT4 map not found (is Cilium running?): %w", err)
	}

	any4Map, _ := findBPFMapByName(ciliumCTAny4MapName)

	// Ensure vmlinux.h exists (NewLoader generates it; if not called yet, generate it).
	if _, err := os.Stat(vmlinuxPath); os.IsNotExist(err) {
		if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
			ct4Map.Close()
			if any4Map != nil {
				any4Map.Close()
			}
			return nil, fmt.Errorf("BTF not available — kernel >= 5.8 required")
		}
		log.Info("Generating vmlinux.h for BPF iterator...")
		vmlinuxFile, err := os.Create(vmlinuxPath)
		if err != nil {
			ct4Map.Close()
			if any4Map != nil {
				any4Map.Close()
			}
			return nil, fmt.Errorf("creating vmlinux.h: %w", err)
		}
		cmd := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c")
		cmd.Stdout = vmlinuxFile
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			vmlinuxFile.Close()
			ct4Map.Close()
			if any4Map != nil {
				any4Map.Close()
			}
			return nil, fmt.Errorf("generating vmlinux.h: %w", err)
		}
		vmlinuxFile.Close()
	}

	// Compile the BPF iterator program.
	log.Info("Compiling BPF iterator program...")
	targetArch := "x86"
	switch runtime.GOARCH {
	case "arm64":
		targetArch = "arm64"
	case "s390x":
		targetArch = "s390"
	case "ppc64le":
		targetArch = "powerpc"
	}
	cmd := exec.Command("clang",
		"-O2", "-g",
		"-target", "bpf",
		"-D__TARGET_ARCH_"+targetArch,
		"-I/tmp",         // vmlinux.h
		"-I/usr/include", // bpf/bpf_helpers.h
		"-c", ciliumIterSourcePath,
		"-o", ciliumIterCompiledPath,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		ct4Map.Close()
		if any4Map != nil {
			any4Map.Close()
		}
		return nil, fmt.Errorf("compiling BPF iterator: %w", err)
	}
	log.Info("BPF iterator compiled")

	// Load the compiled object.
	spec, err := ebpf.LoadCollectionSpec(ciliumIterCompiledPath)
	if err != nil {
		ct4Map.Close()
		if any4Map != nil {
			any4Map.Close()
		}
		return nil, fmt.Errorf("loading BPF iterator spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		ct4Map.Close()
		if any4Map != nil {
			any4Map.Close()
		}
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Errorf("BPF iterator verifier error: %+v", ve)
		}
		return nil, fmt.Errorf("loading BPF iterator objects: %w", err)
	}

	prog := coll.Programs["iter_cilium_ct4"]
	if prog == nil {
		coll.Close()
		ct4Map.Close()
		if any4Map != nil {
			any4Map.Close()
		}
		return nil, fmt.Errorf("BPF program 'iter_cilium_ct4' not found in collection")
	}

	// Attach iterator to the primary CT4 map.
	ct4Iter, err := link.AttachIter(link.IterOptions{
		Program: prog,
		Map:     ct4Map,
	})
	if err != nil {
		coll.Close()
		ct4Map.Close()
		if any4Map != nil {
			any4Map.Close()
		}
		return nil, fmt.Errorf("attaching BPF iterator to %s: %w", ciliumCT4MapName, err)
	}

	// Optionally attach to any4 map.
	var any4Iter *link.Iter
	if any4Map != nil {
		any4Iter, err = link.AttachIter(link.IterOptions{
			Program: prog,
			Map:     any4Map,
		})
		if err != nil {
			log.Warnf("Could not attach BPF iterator to %s (ICMP metrics skipped): %v", ciliumCTAny4MapName, err)
			any4Map.Close()
			any4Map = nil
		}
	}

	outputMap := coll.Maps[ciliumIterMapName]
	if outputMap == nil {
		ct4Iter.Close()
		if any4Iter != nil {
			any4Iter.Close()
		}
		coll.Close()
		ct4Map.Close()
		if any4Map != nil {
			any4Map.Close()
		}
		return nil, fmt.Errorf("output map %q not found in collection", ciliumIterMapName)
	}

	log.Info("BPF iterator attached to Cilium CT maps")
	return &CiliumIterReader{
		coll:       coll,
		ct4Iter:    ct4Iter,
		any4Iter:   any4Iter,
		outputMap:  outputMap,
		ct4ExtMap:  ct4Map,
		any4ExtMap: any4Map,
	}, nil
}

// ReadCounts triggers the BPF iterator and reads the aggregated output map.
// The output map is cleared before each run for snapshot semantics.
func (r *CiliumIterReader) ReadCounts() (map[CiliumCountKey]int64, error) {
	// Clear the output map so we get a fresh snapshot.
	r.clearOutputMap()

	// Trigger the CT4 iterator — the kernel walks the entire map.
	if err := r.triggerIter(r.ct4Iter); err != nil {
		return nil, fmt.Errorf("triggering CT4 iterator: %w", err)
	}

	// Trigger the any4 iterator if attached.
	if r.any4Iter != nil {
		if err := r.triggerIter(r.any4Iter); err != nil {
			log.Warnf("Error triggering any4 iterator: %v", err)
		}
	}

	// Read the small output map and convert to CiliumCountKey.
	return r.readOutputMap()
}

// clearOutputMap deletes all entries from the output map.
func (r *CiliumIterReader) clearOutputMap() {
	var key MapKey
	var keys []MapKey

	iter := r.outputMap.Iterate()
	for iter.Next(&key, new(int64)) {
		keys = append(keys, key)
	}
	for _, k := range keys {
		r.outputMap.Delete(&k)
	}
}

// triggerIter opens the iterator and reads to EOF, which triggers the
// BPF program for every map element. This is a single syscall that
// causes the kernel to walk the map.
func (r *CiliumIterReader) triggerIter(it *link.Iter) error {
	rd, err := it.Open()
	if err != nil {
		return fmt.Errorf("opening iterator: %w", err)
	}
	defer rd.Close()

	// Read to EOF — this triggers the BPF program for each element.
	if _, err := io.Copy(io.Discard, rd); err != nil {
		return fmt.Errorf("reading iterator: %w", err)
	}
	return nil
}

// readOutputMap converts aggregated MapKey entries to CiliumCountKey.
func (r *CiliumIterReader) readOutputMap() (map[CiliumCountKey]int64, error) {
	result := make(map[CiliumCountKey]int64)

	var key MapKey
	var value int64

	iter := r.outputMap.Iterate()
	for iter.Next(&key, &value) {
		if value <= 0 {
			continue
		}

		proto, ok := ProtoNames[key.Proto]
		if !ok {
			proto = "other"
		}

		direction, ok := DirectionNames[key.Direction]
		if !ok {
			direction = "source"
		}

		ip := mapKeyIPToString(key.IP)
		ck := CiliumCountKey{IP: ip, Protocol: proto, Direction: direction}
		result[ck] += value
	}

	if err := iter.Err(); err != nil {
		if errors.Is(err, ebpf.ErrIterationAborted) {
			log.Warn("Output map iteration aborted, partial results returned")
			return result, nil
		}
		return nil, fmt.Errorf("iterating output map: %w", err)
	}

	return result, nil
}

// mapKeyIPToString converts a uint32 IPv4 address (network byte order) to
// dotted-decimal string.
func mapKeyIPToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24))
}

// Close detaches iterators and closes all BPF resources.
func (r *CiliumIterReader) Close() error {
	var errs []error
	if r.ct4Iter != nil {
		errs = append(errs, r.ct4Iter.Close())
	}
	if r.any4Iter != nil {
		errs = append(errs, r.any4Iter.Close())
	}
	if r.coll != nil {
		r.coll.Close()
	}
	if r.ct4ExtMap != nil {
		errs = append(errs, r.ct4ExtMap.Close())
	}
	if r.any4ExtMap != nil {
		errs = append(errs, r.any4ExtMap.Close())
	}
	return errors.Join(errs...)
}
