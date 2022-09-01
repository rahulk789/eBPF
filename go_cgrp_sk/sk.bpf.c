// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
char __license[] SEC("license") = "Dual MIT/GPL";


struct bpf_map_def SEC("maps") pkt_count = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

SEC("tracepoint/syscalls/sys_enter_execve")

int getp(void *ctx)
{   char d[100];
  int key=4040;
   u64 c =  bpf_get_current_cgroup_id(void)
   bpf_get_current_comm(&d, sizeof(d));
   if (c == d){
   key= bpf_map_lookup_elem(&events,&key);
   bpf_map_update_elem(&events,&key,&d,BPF_ANY);}
   return 0;
}

SEC("cgroup_skb/egress")
int count_egress_packets(struct __sk_buff *skb) {
	u32 key      = 0;
	u64 init_val = 1;
    bpf_get_cgroup_classid() 
	u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
	if (!count) {
		bpf_map_update_elem(&pkt_count, &key, &init_val, BPF_ANY);
		return 1;
	}
	__sync_fetch_and_add(count, 1);

	return 1;
}

