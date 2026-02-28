//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define BPF_ANY 0

// Protocol buckets — must match Go constants in types.go and conntrack.c
#define PROTO_TCP   0
#define PROTO_UDP   1
#define PROTO_OTHER 2

// Direction — must match Go constants in types.go and conntrack.c
#define DIR_SOURCE 0
#define DIR_DEST   1

#define DNS_PORT __bpf_constant_htons(53)

// map_key matches conntrack.c — reuse the same Go MapKey type.
struct map_key {
    __u32 ip;
    __u8  proto;
    __u8  direction;
    __u8  pad[2];
};

// dns_key is just an IP — used for the DNS output map.
struct dns_key {
    __u32 ip;
};

// Cilium's ipv4_ct_tuple layout (14 bytes, packed).
struct cilium_ct4_tuple {
    __u32 dest_addr;
    __u32 source_addr;
    __u16 dest_port;
    __u16 source_port;
    __u8  nexthdr;
    __u8  flags;
} __attribute__((packed));

// Output map: aggregated counts per (ip, proto, direction).
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct map_key);
    __type(value, __s64);
} cilium_iter_counts SEC(".maps");

// DNS output map: counts of port-53 CT entries per IP.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct dns_key);
    __type(value, __s64);
} cilium_iter_dns SEC(".maps");

static __always_inline __u8 classify_proto(__u8 nexthdr) {
    if (nexthdr == 6)  return PROTO_TCP;
    if (nexthdr == 17) return PROTO_UDP;
    return PROTO_OTHER;
}

static __always_inline void bump_count(struct map_key *key) {
    __s64 *val = bpf_map_lookup_elem(&cilium_iter_counts, key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __s64 one = 1;
        bpf_map_update_elem(&cilium_iter_counts, key, &one, BPF_ANY);
    }
}

static __always_inline void bump_dns(struct dns_key *key) {
    __s64 *val = bpf_map_lookup_elem(&cilium_iter_dns, key);
    if (val) {
        __sync_fetch_and_add(val, 1);
    } else {
        __s64 one = 1;
        bpf_map_update_elem(&cilium_iter_dns, key, &one, BPF_ANY);
    }
}

// iter/bpf_map_elem — called once per element of the attached map.
// The kernel walks the map entirely in kernel space; we just aggregate.
SEC("iter/bpf_map_elem")
int iter_cilium_ct4(struct bpf_iter__bpf_map_elem *ctx) {
    struct cilium_ct4_tuple *tuple = ctx->key;

    // NULL key signals end-of-iteration.
    if (!tuple)
        return 0;

    // Skip reply-direction entries (flags bit 0 set).
    // Cilium stores two entries per connection; counting both doubles metrics.
    if (tuple->flags & 0x1)
        return 0;

    // Separate DNS (port 53) entries from regular counts.
    if (tuple->source_port == DNS_PORT || tuple->dest_port == DNS_PORT) {
        struct dns_key src_dns = { .ip = tuple->source_addr };
        struct dns_key dst_dns = { .ip = tuple->dest_addr };
        bump_dns(&src_dns);
        bump_dns(&dst_dns);
    } else {
        __u8 proto = classify_proto(tuple->nexthdr);

        struct map_key src_key = {};
        src_key.ip        = tuple->source_addr;
        src_key.proto     = proto;
        src_key.direction = DIR_SOURCE;
        bump_count(&src_key);

        struct map_key dst_key = {};
        dst_key.ip        = tuple->dest_addr;
        dst_key.proto     = proto;
        dst_key.direction = DIR_DEST;
        bump_count(&dst_key);
    }

    return 0;
}
