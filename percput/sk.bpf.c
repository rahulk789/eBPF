// +build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#define htons(x) bpf_htons(x)
char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_def SEC("maps") pkt_count = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 1,
};

SEC("cgroup_skb/egress")
int count_egress_packets(struct __sk_buff *skb) {
	
	__u32 key      = 0;
	__u64 init_val = 1;
	u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
	if (!count) {
		bpf_map_update_elem(&pkt_count, &key, &init_val, BPF_ANY);
	}
	else {
	__sync_fetch_and_add(count, 1);
	}
	struct ethhdr *eth = (void *)(long)skb->data;
    	struct iphdr *ip = (void *)(long)(skb->data + sizeof(struct ethhdr));
    	if (ip->protocol == IPPROTO_TCP) {
    		struct tcphdr *tcp = (void *)(long)(skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    		if (tcp->dest == htons(4040)) {
        		return true;
		}
	}
    return false;

}
