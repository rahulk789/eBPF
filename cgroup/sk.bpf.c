// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
char __license[] SEC("license") = "Dual MIT/GPL";

/* 
 * bare minimum , we need pid and lport in the map . The map has to be perf/ring because array map cant hold so many values.
 * we will be using what program???????? kprobe/execve for now and for dropping we will use xdp egress ig
 */

struct event_data {
    u64 pid;
    u64 lport;
    u8 comm[16];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1 << 24);
} pidcheck SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

const struct event_data *unused __attribute__((unused));

SEC("kprobe/sys_execve")
int kprobe_execve(struct pt_regs *ctx,const struct sockaddr *addr)
{ 
   struct event_data *evt;
   int key= 4040;
   
   evt =  bpf_ringbuf_reserve(&events, sizeof(struct event_data),0);
   if (!evt) return 0;
   evt->pid =  bpf_get_current_pid_tgid();
   evt->pid = evt->pid >> 32;
   
   bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
   
   struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
   evt.lport = in_addr->sin_port;
   evt.lport = ntohs(evt.lport);
   
   bpf_ringbuf_submit(evt,0);
   
   //key= bpf_map_lookup_elem(&pidcheck,&key);
   if (key == evt->pid){
   }
   return 0;
}

SEC("xdp")
int packet_dropper(struct __sk_buff *skb) {
	return 1;
}

