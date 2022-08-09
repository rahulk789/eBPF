// +build ignore
#define KBUILD_MODNAME "xdp_filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/tty.h>
#include <netinet/in.h>
#include <linux/types.h>
struct bpf_map_def SEC("maps") counter = {
      .type = BPF_MAP_TYPE_ARRAY,
      .key_size = sizeof(__u32),
      .value_size = sizeof(long),
      .max_entries = 256,
};
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
          __u64 value = htons(tcp->dest);
          // u64 source = ntohs(tcp->dest);
//          counter.Put(value);
          //if (value)
              //__sync_fetch_and_add(value, 1);
          if (value == 4040) // && x != -1)
            return XDP_PASS;
          else if (value != 4040) // && x != -1 )
            return XDP_DROP;
        }
      }
    }
  }
  return XDP_PASS;
}
