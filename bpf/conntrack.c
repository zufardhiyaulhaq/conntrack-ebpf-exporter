//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/* BPF_ANY is a #define, not in kernel BTF / vmlinux.h */
#define BPF_ANY 0

// Protocol buckets — must match Go constants in types.go
#define PROTO_TCP   0
#define PROTO_UDP   1
#define PROTO_OTHER 2

// Direction — must match Go constants in types.go
#define DIR_SOURCE 0
#define DIR_DEST   1

struct map_key {
    __u32 ip;         /* IPv4 address in network byte order */
    __u8  proto;      /* 0=tcp, 1=udp, 2=other */
    __u8  direction;  /* 0=source, 1=destination */
    __u8  pad[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct map_key);
    __type(value, __s64);
} conntrack_counts SEC(".maps");

static __always_inline __u8 get_proto_bucket(struct nf_conn *ct) {
    __u8 protonum;
    protonum = BPF_CORE_READ(ct, tuplehash[0].tuple.dst.protonum);

    if (protonum == IPPROTO_TCP) {
        return PROTO_TCP;
    }

    if (protonum == IPPROTO_UDP) {
        return PROTO_UDP;
    }

    return PROTO_OTHER;
}

static __always_inline void update_count(struct map_key *key, __s64 delta) {
    __s64 *val = bpf_map_lookup_elem(&conntrack_counts, key);
    if (val) {
        __s64 new_val = __sync_fetch_and_add(val, delta) + delta;
        if (delta < 0 && new_val <= 0) {
            bpf_map_delete_elem(&conntrack_counts, key);
        }
    } else if (delta > 0) {
        __s64 initval = delta;
        bpf_map_update_elem(&conntrack_counts, key, &initval, BPF_ANY);
    }
}

// Note: The decrement and delete are non-atomic. A concurrent count_insert on
// another CPU could increment between the two operations, and the subsequent
// delete would lose that insert. This is an accepted tradeoff — the goal is
// finding offending pods (100K+ entries), not exact per-entry accounting.
// Stale zero entries are harmless (userspace skips count <= 0).
static __always_inline void count_entries(struct nf_conn *ct, __s64 delta) {
    __u8 proto = get_proto_bucket(ct);
    __u32 src_ip = BPF_CORE_READ(ct, tuplehash[0].tuple.src.u3.ip);
    __u32 dst_ip = BPF_CORE_READ(ct, tuplehash[0].tuple.dst.u3.ip);

    struct map_key src_key = {};
    src_key.ip = src_ip;
    src_key.proto = proto;
    src_key.direction = DIR_SOURCE;

    struct map_key dst_key = {};
    dst_key.ip = dst_ip;
    dst_key.proto = proto;
    dst_key.direction = DIR_DEST;

    update_count(&src_key, delta);
    update_count(&dst_key, delta);
}

SEC("kprobe/nf_conntrack_hash_check_insert")
int BPF_KPROBE(kprobe_ct_insert, struct nf_conn *ct) {
    count_entries(ct, 1);
    return 0;
}

SEC("kprobe/nf_ct_delete")
int BPF_KPROBE(kprobe_ct_delete, struct nf_conn *ct) {
    count_entries(ct, -1);
    return 0;
}
