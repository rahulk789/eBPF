// +build ignore

//#include "vmlinux.h"
//#include <bpf/bpf_helpers.h>
//#include <bpf/bpf_endian.h>
//#include <bpf/bpf_tracing.h>

#include "../headers/common.h"

#include "../headers/bpf_endian.h"
#include "../headers/bpf_tracing.h"
#define AF_INET 2
#define AF_INET6 10

#define AF_INET 2
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";
struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		// Padding out union skc_hash.
		__u32 _;
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
};

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
struct sock {
	struct sock_common __sk_common;
};
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

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

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
	tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
	tcp_info->daddr = sk->__sk_common.skc_daddr;
	tcp_info->dport = sk->__sk_common.skc_dport;
	tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);

	bpf_get_current_comm(&tcp_info->comm, TASK_COMM_LEN);

	bpf_ringbuf_submit(tcp_info, 0);

	return 0;
}
SEC("socket")
int socket(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;

  if ((void *)eth + sizeof(*eth) <= data_end) {

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) <= data_end) {

      if (ip->protocol == IPPROTO_TCP) {

        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) <= data_end) {
          u64 value = (tcp->dest);
          if (value != 4040)//  && x != "myprocess" )
            return XDP_PASS;
          else if (value == 4040)//  && x != "myprocess" )
            return XDP_DROP;
        }
      }
    }
  }
  return XDP_PASS;
}
