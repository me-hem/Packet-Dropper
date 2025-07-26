//go:build ignore
#include "common.h"
#include "bpf_endian.h"
#include <stdbool.h>

char __license[] SEC("license") = "GPL";

#define CC_ATC_OK 1
#define CC_ATC_DROP 0
#define IPPROTO_TCP 6
#define PROCESS_MAX_LEN 16
#define ALLOWED_PORT 4040

// Structure to store dropped packet statistics
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped_pkt_count SEC(".maps");


// Function to check whether protocol is TCP or not
int is_tcp(struct bpf_sock_addr *ctx) {
    return (ctx->protocol == IPPROTO_TCP) ? 1 : 0;
}


// Function to match destination port
int match_dport(struct bpf_sock_addr *ctx) {
    __u16 dport = bpf_ntohs(ctx->user_port);
    return (dport == ALLOWED_PORT) ? 1 : 0;
}


// Function to match process name
int match_process_name() {
    char pname[PROCESS_MAX_LEN];
    bpf_get_current_comm(&pname, sizeof(pname));
    char target[] = "myprocess";
    
    #pragma unroll
    for (int i = 0; i < sizeof(target) - 1; i++) {
        if (i >= PROCESS_MAX_LEN - 1 || pname[i] != target[i])
            return 0;
    }
    return 1;
}


// Function to filter packets
SEC("cgroup/connect4")
int ingress_prog_func(struct bpf_sock_addr *ctx) {
    if (!is_tcp(ctx))
        return CC_ATC_OK;
    
    if (match_process_name()) {
        if (!match_dport(ctx)) {
            __u32 key = 0;
            __u64 *value = bpf_map_lookup_elem(&dropped_pkt_count, &key);
            if (value)
                __sync_fetch_and_add(value, 1);
            return CC_ATC_DROP;
        }
    }
    
    return CC_ATC_OK;
}