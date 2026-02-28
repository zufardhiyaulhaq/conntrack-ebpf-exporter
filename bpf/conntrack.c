//go:build ignore

/*
 * Kernel integer types required by BPF helper headers.
 * Defined here so we don't need vmlinux.h or linux/types.h
 * (which pulls in asm/types.h, unavailable in -target bpf).
 */
typedef unsigned char      __u8;
typedef unsigned short     __u16;
typedef unsigned int       __u32;
typedef unsigned long long __u64;
typedef long long          __s64;

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/*
 * Minimal kernel struct definitions for CO-RE.
 *
 * Only the fields accessed by this program are defined. At load time,
 * CO-RE resolves actual field offsets from the running kernel's BTF
 * (/sys/kernel/btf/vmlinux). This makes the program portable across
 * kernel versions without requiring vmlinux.h at compile time.
 */

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

enum tcp_conntrack {
    TCP_CONNTRACK_NONE,
    TCP_CONNTRACK_SYN_SENT,
    TCP_CONNTRACK_SYN_RECV,
    TCP_CONNTRACK_ESTABLISHED,
    TCP_CONNTRACK_FIN_WAIT,
    TCP_CONNTRACK_CLOSE_WAIT,
    TCP_CONNTRACK_LAST_ACK,
    TCP_CONNTRACK_TIME_WAIT,
    TCP_CONNTRACK_CLOSE,
    TCP_CONNTRACK_LISTEN,
    TCP_CONNTRACK_MAX,
};

struct ns_common {
    unsigned int inum;
} __attribute__((preserve_access_index));

struct net {
    struct ns_common ns;
} __attribute__((preserve_access_index));

struct nf_conntrack_tuple_dst {
    union {
        __u16 all;
    } u;
    __u8 protonum;
} __attribute__((preserve_access_index));

struct nf_conntrack_tuple {
    struct nf_conntrack_tuple_dst dst;
} __attribute__((preserve_access_index));

struct nf_conntrack_tuple_hash {
    struct nf_conntrack_tuple tuple;
} __attribute__((preserve_access_index));

struct nf_ct_tcp {
    __u8 state;
} __attribute__((preserve_access_index));

union nf_conntrack_proto {
    struct nf_ct_tcp tcp;
} __attribute__((preserve_access_index));

struct nf_conn {
    struct nf_conntrack_tuple_hash tuplehash[2];
    struct {
        struct net *net;
    } ct_net;
    union nf_conntrack_proto proto;
} __attribute__((preserve_access_index));

/* --- End kernel type definitions --- */

// State buckets — must match Go constants in types.go
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

static __always_inline __u32 get_netns_inode(struct nf_conn *ct) {
    return BPF_CORE_READ(ct, ct_net.net, ns.inum);
}

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

// Note: The decrement and delete are non-atomic. A concurrent count_insert on
// another CPU could increment between the two operations, and the subsequent
// delete would lose that insert. This is an accepted tradeoff — the goal is
// finding offending pods (100K+ entries), not exact per-entry accounting.
// Stale zero entries are harmless (userspace skips count <= 0).
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

SEC("kprobe/nf_conntrack_hash_check_insert")
int BPF_KPROBE(kprobe_ct_insert, struct nf_conn *ct) {
    count_insert(ct);
    return 0;
}

SEC("kprobe/nf_ct_delete")
int BPF_KPROBE(kprobe_ct_delete, struct nf_conn *ct) {
    count_delete(ct);
    return 0;
}
