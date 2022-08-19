// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
char __license[] SEC("license") = "Dual MIT/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")

int getp(void *ctx)
{   char d[100];
    bpf_get_current_comm(&d, sizeof(d));
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &d, sizeof(d));
    return 0;
}

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;

  if ((void *)eth + sizeof(*eth) <= data_end) {

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) <= data_end) {

      if (ip->protocol == IPPROTO_TCP) {

        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
          u64 value = (tcp->dest);
//          counter.Put(value);
          //if (value)
            //  __sync_fetch_and_add(value, 1);
          if (value == 4040)//  && x != "myprocess" )
            return XDP_PASS;
          else if (value != 4040)//  && x != "myprocess" )
            return XDP_DROP;
        }
      }
    }
  }
  return XDP_PASS;
}
