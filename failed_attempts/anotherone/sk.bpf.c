// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
char __license[] SEC("license") = "Dual MIT/GPL";
enum {
    _DO_EXIT = 351,
    _SYS_RMDIR = 84,

    _SYS_PTRACE = 101,         
    // lsm
    _SECURITY_BPRM_CHECK = 352,

    // accept/connect
    _TCP_CONNECT = 400,
    _TCP_ACCEPT = 401,
    _TCP_CONNECT_v6 = 402,
    _TCP_ACCEPT_v6 = 403,
};
/* 
 * bare minimum , we need pid and lport in the map . The map has to be perf/ring because array map cant hold so many values.
 * we will be using what program???????? kprobe/execve for now and for dropping we will use xdp egress ig
 */

static __always_inline int get_connection_info(struct sock_common *conn,struct sockaddr_in *sockv4, struct sockaddr_in6 *sockv6,sys_context_t *context, args_t *args, u32 event ) {
    switch (conn->skc_family)
    {
    case AF_INET:
        sockv4->sin_family = conn->skc_family;
        sockv4->sin_addr.s_addr = conn->skc_daddr;
        sockv4->sin_port = (event == _TCP_CONNECT) ? conn->skc_dport : (conn->skc_num>>8) | (conn->skc_num<<8);
        args->args[1] = (unsigned long) sockv4;
        context->event_id = (event == _TCP_CONNECT) ? _TCP_CONNECT : _TCP_ACCEPT ;
        break;
    
    case AF_INET6:
        sockv6->sin6_family = conn->skc_family;
        sockv6->sin6_port = (event == _TCP_CONNECT) ? conn->skc_dport : (conn->skc_num>>8) | (conn->skc_num<<8);
        bpf_probe_read(&sockv6->sin6_addr.in6_u.u6_addr16, sizeof(sockv6->sin6_addr.in6_u.u6_addr16), conn->skc_v6_daddr.in6_u.u6_addr16);
        args->args[1] = (unsigned long) sockv6;
        context->event_id = (event == _TCP_CONNECT) ? _TCP_CONNECT_v6 : _TCP_ACCEPT_v6 ;
        break;

    default:
        return 1;
    }

    return 0;
}

SEC("kprobe/__x64_sys_tcp_connect")
int kprobe__tcp_connect(struct pt_regs *ctx){
    if (skip_syscall())
		return 0;

    struct sock *sk = (struct sock *) PT_REGS_PARM1(ctx);
    struct sock_common conn = READ_KERN(sk->__sk_common);
    struct sockaddr_in sockv4;
    struct sockaddr_in6 sockv6;
    
    sys_context_t context = {};
    args_t args = {};
    u64 types = ARG_TYPE0(STR_T)|ARG_TYPE1(SOCKADDR_T);

    init_context(&context);
    context.argnum = get_arg_num(types);
    
    if (get_connection_info(&conn, &sockv4, &sockv6, &context, &args, _TCP_CONNECT) != 0 ) {
        return 0;
    }

    args.args[0] = (unsigned long) conn.skc_prot->name;
    set_buffer_offset(DATA_BUF_TYPE, sizeof(sys_context_t));
    bufs_t *bufs_p = get_buffer(DATA_BUF_TYPE);
    if (bufs_p == NULL)
        return 0;
    save_context_to_buffer(bufs_p, (void*)&context);
    save_args_to_buffer(types, &args);
    events_perf_submit(ctx);

    return 0;
}
