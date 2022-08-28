// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
char __license[] SEC("license") = "Dual MIT/GPL";
/*
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
    __uint(max_entries, 1);
} events SEC(".maps");

{   char d[100];
    char c[100] = "myprocess"
  int key=4040;
   bpf_get_current_comm(&d, sizeof(d));
   if (c == d){
   key= bpf_map_lookup_elem(&events,&key);
   bpf_map_update_elem(&events,&key,&d,BPF_ANY);}
   return 0;
*/
SEC("socket")
int sk_filter(struct __sk_buff *skb) {
  char d[100];
  char c[100] = "myprocess";
  bpf_get_current_comm(&d, sizeof(d));
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
//          char d[100];
 //         bpf_get_current_comm(&d, sizeof(d));
    //valp= bpf_map_lookup_elem(&events,&key);
  //        bpf_map_update_elem(&events,&value,NULL,BPF_ANY);

          //          counter.Put(value);
          //if (value)
            //  __sync_fetch_and_add(value, 1);
          if (value == 4040 && d != c )
            return SK_PASS;
          else if (value != 4040 && d != c )
            return SK_DROP;
        }
      }
    }
  }
  return SK_PASS;
}
