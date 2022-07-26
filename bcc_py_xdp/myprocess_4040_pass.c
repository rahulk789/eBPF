
#define KBUILD_MODNAME "myprocess_4040_pass"
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pid.h>
#include <linux/tty.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <uapi/linux/ptrace.h>
//pid_t pid = task_pid_nr(current);
//x = pid_nr(get_task_pid(current, PIDTYPE_PID))
//struct task_struct *p;
//for_each_process(p) {
//	if(p->comm == "myprocess")
//		int x= task_pid_nr(p);
//}

BPF_HISTOGRAM(counter, u64);

int myprocess_4040_pass(struct xdp_md *ctx)
{   char data1[100];
    bpf_get_current_comm(&data1, 100);
    
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)eth + sizeof(*eth) <= data_end)
    {

        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(*ip) <= data_end)
        {

            if (ip->protocol == IPPROTO_TCP)
            {

                struct tcphdr *tcp = (void *)ip + sizeof(*ip);
                if ((void *)tcp + sizeof(*tcp) <= data_end)
                {
                    u64 value = htons(tcp->dest);
		    //u64 source = ntohs(tcp->dest);
                    counter.increment(value);
		    if (value == 4040)// && x != -1)
			    return XDP_PASS;
		    else if (value != 4040)// && x != -1 )
			    return XDP_DROP;
                }
            }
        }
    }
    return XDP_PASS;
}
