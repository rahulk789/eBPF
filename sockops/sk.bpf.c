// +build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

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
		return 1;
	}
	__sync_fetch_and_add(count, 1);
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end) {
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (void *)ip + sizeof(*ip);
                if ((void *)tcp + sizeof(*tcp) <= data_end) {
                    u64 value = tcp->dest;
                    if (value == 4040)
                    return SK_PASS;
                    else if (value != 4040)
                    return SK_DROP;
                }
            }
        }
    }
return SK_PASS;
}

