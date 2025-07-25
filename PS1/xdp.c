//go:build ignore

#include "common.h"
#include "bpf_endian.h"
#include <stdbool.h>

#define IPPROTO_TCP 6

char __license[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped_pkt_count SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} drop_port_config SEC(".maps");



struct iphdr* get_iphdr(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return NULL;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return NULL;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return NULL;

    return iph;
}


int is_tcp(struct iphdr *iph) {
    return (iph->protocol == IPPROTO_TCP) ? IPPROTO_TCP : 0;
}


int match_dport(struct xdp_md *ctx, struct iphdr *iph) {
    void *data_end = (void *)(long)ctx->data_end;

    int ip_header_len = iph->ihl * 4;
    struct tcphdr *tcph = (void *)iph + ip_header_len;
    if ((void *)(tcph + 1) > data_end)
        return 0;

    __u32 key = 0;
    __u16 *port = bpf_map_lookup_elem(&drop_port_config, &key);

    if (!port)
        return 0;

    if (tcph->dest == bpf_htons(*port))
        return 1;

    return 0;
}



SEC("xdp")
int ingress_prog_func(struct xdp_md *ctx) {
    struct iphdr *iph = get_iphdr(ctx);
    if (!iph)
        return XDP_PASS;

    if (!is_tcp(iph))
        return XDP_PASS;

    if (match_dport(ctx, iph)) {
        __u32 key = 0;
        __u64 *value = bpf_map_lookup_elem(&dropped_pkt_count, &key);
        if (value)
            __sync_fetch_and_add(value, 1);
        return XDP_DROP;
    }

    return XDP_PASS;
}
