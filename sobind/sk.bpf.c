// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

#define AF_INET 2
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event {
	u8 comm[16];
	__u16 sport;
	__be16 dport;
	__be32 saddr;
	__be32 daddr;
};
struct event *unused __attribute__((unused));

SEC("fentry/tcp_connect")
int BPF_PROG(tcp_connect, struct sock *sk) {
	if (sk->__sk_common.skc_family != AF_INET) {
		return 0;
	}

	struct event *tcp_info;
	tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
	if (!tcp_info) {
		return 0;
	}
    bpf_probe_read(&sk, sizeof(sk), (void *)PT_REGS_PARM1(ctx));
	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->daddr = sk->__sk_common.skc_daddr;
	tcp_info->dport = sk->__sk_common.skc_dport;
	tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);

	bpf_get_current_comm(&tcp_info->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}/*
SEC("socket")
int dropper(struct __sk_buff *skb) {
    struct ethhdr *eth = (void *)(long)skb->data;
    	struct iphdr *ip = (void *)(long)(skb->data + sizeof(struct ethhdr));
    	if (ip->protocol == IPPROTO_TCP) {
    		struct tcphdr *tcp = (void *)(long)(skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    		if (tcp->dest == htons(4040)) {
        		return 1;
		}
	}
        return 0;
}*/
