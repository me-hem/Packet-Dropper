// This is a compact version of `vmlinux.h` to be used in the examples using C code.

#pragma once

typedef unsigned char __u8;
typedef short int __s16;
typedef short unsigned int __u16;
typedef int __s32;
typedef unsigned int __u32;
typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u8 u8;
typedef __s16 s16;
typedef __u16 u16;
typedef __s32 s32;
typedef __u32 u32;
typedef __s64 s64;
typedef __u64 u64;
typedef __u16 __le16;
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u32 __wsum;

#include "bpf_helpers.h"

#define __bpf_md_ptr(type, name)	\
union {					\
	type name;			\
	__u64 :64;			\
} __attribute__((aligned(8)))


enum bpf_map_type {
	BPF_MAP_TYPE_UNSPEC                = 0,
	BPF_MAP_TYPE_HASH                  = 1,
	BPF_MAP_TYPE_ARRAY                 = 2,
	BPF_MAP_TYPE_PROG_ARRAY            = 3,
	BPF_MAP_TYPE_PERF_EVENT_ARRAY      = 4,
	BPF_MAP_TYPE_PERCPU_HASH           = 5,
	BPF_MAP_TYPE_PERCPU_ARRAY          = 6,
	BPF_MAP_TYPE_STACK_TRACE           = 7,
	BPF_MAP_TYPE_CGROUP_ARRAY          = 8,
	BPF_MAP_TYPE_LRU_HASH              = 9,
	BPF_MAP_TYPE_LRU_PERCPU_HASH       = 10,
	BPF_MAP_TYPE_LPM_TRIE              = 11,
	BPF_MAP_TYPE_ARRAY_OF_MAPS         = 12,
	BPF_MAP_TYPE_HASH_OF_MAPS          = 13,
	BPF_MAP_TYPE_DEVMAP                = 14,
	BPF_MAP_TYPE_SOCKMAP               = 15,
	BPF_MAP_TYPE_CPUMAP                = 16,
	BPF_MAP_TYPE_XSKMAP                = 17,
	BPF_MAP_TYPE_SOCKHASH              = 18,
	BPF_MAP_TYPE_CGROUP_STORAGE        = 19,
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY   = 20,
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE = 21,
	BPF_MAP_TYPE_QUEUE                 = 22,
	BPF_MAP_TYPE_STACK                 = 23,
	BPF_MAP_TYPE_SK_STORAGE            = 24,
	BPF_MAP_TYPE_DEVMAP_HASH           = 25,
	BPF_MAP_TYPE_STRUCT_OPS            = 26,
	BPF_MAP_TYPE_RINGBUF               = 27,
	BPF_MAP_TYPE_INODE_STORAGE         = 28,
};

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP = 1,
	XDP_PASS = 2,
	XDP_TX = 3,
	XDP_REDIRECT = 4,
};

enum tc_action {
	TC_ACT_UNSPEC 		= -1,
	TC_ACT_OK 			= 0,
	TC_ACT_RECLASSIFY 	= 1,
	TC_ACT_SHOT 		= 2,
	TC_ACT_PIPE 		= 3,
	TC_ACT_STOLEN 		= 4,
	TC_ACT_QUEUED 		= 5,
	TC_ACT_REPEAT 		= 6,
	TC_ACT_REDIRECT 	= 7,
	TC_ACT_JUMP 		= 0x10000000
};

struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	__u32 ingress_ifindex;
	__u32 rx_queue_index;
	__u32 egress_ifindex;
};

struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;

	/* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
	__u32 family;
	__u32 remote_ip4;	/* Stored in network byte order */
	__u32 local_ip4;	/* Stored in network byte order */
	__u32 remote_ip6[4];	/* Stored in network byte order */
	__u32 local_ip6[4];	/* Stored in network byte order */
	__u32 remote_port;	/* Stored in network byte order */
	__u32 local_port;	/* stored in host byte order */
	/* ... here. */

	__u32 data_meta;
	__bpf_md_ptr(struct bpf_flow_keys *, flow_keys);
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__bpf_md_ptr(struct bpf_sock *, sk);
	__u32 gso_size;
	__u8  tstamp_type;
	__u32 :24;		/* Padding, future use. */
	__u64 hwtstamp;
};

struct bpf_sock_addr {
	__u32 user_family;	/* Allows 4-byte read, but no write. */
	__u32 user_ip4;		/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 user_ip6[4];	/* Allows 1,2,4,8-byte read and 4,8-byte write.
				 * Stored in network byte order.
				 */
	__u32 user_port;	/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order
				 */
	__u32 family;		/* Allows 4-byte read, but no write */
	__u32 type;		/* Allows 4-byte read, but no write */
	__u32 protocol;		/* Allows 4-byte read, but no write */
	__u32 msg_src_ip4;	/* Allows 1,2,4-byte read and 4-byte write.
				 * Stored in network byte order.
				 */
	__u32 msg_src_ip6[4];	/* Allows 1,2,4,8-byte read and 4,8-byte write.
				 * Stored in network byte order.
				 */
	__bpf_md_ptr(struct bpf_sock *, sk);
};

typedef __u16 __sum16;

#define ETH_P_IP 0x0800

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__be16 h_proto;
};

struct iphdr {
	__u8 ihl: 4;
	__u8 version: 4;
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
};


struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

enum {
	BPF_ANY     = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST   = 2,
	BPF_F_LOCK  = 4,
};

/* BPF_FUNC_perf_event_output, BPF_FUNC_perf_event_read and
 * BPF_FUNC_perf_event_read_value flags.
 */
#define BPF_F_INDEX_MASK 0xffffffffULL
#define BPF_F_CURRENT_CPU BPF_F_INDEX_MASK

#if defined(__TARGET_ARCH_x86)
struct pt_regs {
	/*
	 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
	 * unless syscall needs a complete, fully filled "struct pt_regs".
	 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long rbp;
	unsigned long rbx;
	/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rsi;
	unsigned long rdi;
	/*
	 * On syscall entry, this is syscall#. On CPU exception, this is error code.
	 * On hw interrupt, it's IRQ number:
	 */
	unsigned long orig_rax;
	/* Return frame for iretq */
	unsigned long rip;
	unsigned long cs;
	unsigned long eflags;
	unsigned long rsp;
	unsigned long ss;
	/* top of stack page */
};
#endif /* __TARGET_ARCH_x86 */
