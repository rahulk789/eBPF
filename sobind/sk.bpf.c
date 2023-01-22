// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10
char __license[] SEC("license") = "Dual MIT/GPL";

// Common structure for UDP/TCP IPv4/IPv6
struct bind_events {
    u64 pid_tgid;
    u64 proto;    
    u64 lport;    
    struct in6_addr laddr; 
    u8 task[80];
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

const struct bind_events *unused __attribute__((unused));

SEC("kprobe/inet_bind")
// Send an event for each IPv4 bind with PID, bound address and port
int inet_bind(struct pt_regs *ctx, struct sock *sk)
{
        struct bind_events *evt;
        evt = bpf_ringbuf_reserve(&events, sizeof(struct bind_events),0);
        if (!evt) return 0;
        u64 pid = bpf_get_current_pid_tgid();
        pid = pid >> 32 ;
        evt->pid_tgid=pid; 

        u8 protocol = 0;
        u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
        evt->proto = family << 16 | protocol;

        evt->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
        evt->laddr = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);

        bpf_get_current_comm(evt->task, 80);
        bpf_ringbuf_submit(evt,0);
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
