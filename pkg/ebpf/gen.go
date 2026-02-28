//go:build ignore

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type map_key -target amd64 conntrack ../../bpf/conntrack.c
