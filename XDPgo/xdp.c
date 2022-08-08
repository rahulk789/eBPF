// +build ignore
#include "bpf_endian.h"
#include "common.h"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/sched.h>

SEC("xdp")
BPF_HISTOGRAM(counter, u64);

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
          u64 value = htons(tcp->dest);
          // u64 source = ntohs(tcp->dest);
          counter.increment(value);
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
