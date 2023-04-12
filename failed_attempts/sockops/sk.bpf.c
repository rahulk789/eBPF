// +build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#define htons(x) bpf_htons(x)
char __license[] SEC("license") = "Dual MIT/GPL";

/*struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_def SEC("maps") socket_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u64),
	.max_entries = 1,
};
*/
SEC("socket")
int dropper(struct __sk_buff *skb) {
//    struct ethhdr *eth = (void *)(long)skb->data;
    	struct iphdr *ip = (void *)(long)(skb->data + sizeof(struct ethhdr));
    	if (ip->protocol == IPPROTO_TCP) {
    		struct tcphdr *tcp = (void *)(long)(skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    		if (tcp->dest == htons(4040)) {
        		return 1;
		}
	}
        return 0;
}

