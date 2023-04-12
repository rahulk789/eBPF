#include <linux/filter.h>
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#define PORT 9090
int main() {
int sock;
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock<0){
    perror("socket failed lol");
    exit(0);}
struct sockaddr_in address;
struct sock_filter bpf_bytecode[] = {
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 0, 6, 0x000086dd },
{ 0x30, 0, 0, 0x00000014 },
{ 0x15, 0, 15, 0x00000006 },
{ 0x28, 0, 0, 0x00000036 },
{ 0x15, 12, 0, 0x00000fc8 },
{ 0x28, 0, 0, 0x00000038 },
{ 0x15, 10, 11, 0x00000fc8 },
{ 0x15, 0, 10, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 8, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 6, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 2, 0, 0x00000fc8 },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 0, 1, 0x00000fc8 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },}; 
int addrlen = sizeof(address);
struct sock_fprog bpf_program = { sizeof(bpf_bytecode) / sizeof(bpf_bytecode[0]), bpf_bytecode};
int err = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program));
if (err) {
    perror("sockop fail lol");
    exit(0);
}
int opt=1;
    if (setsockopt(sock, SOL_SOCKET,
                   SO_REUSEADDR | SO_REUSEPORT, &opt,
                   sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
address.sin_family = AF_INET;
address.sin_addr.s_addr = INADDR_ANY;
address.sin_port = htons(PORT);
int a=bind(sock,(struct sockaddr*)&address,addrlen);
if (a<0) {
    perror("bind error bro");
    exit(0);
}
if (listen(sock,3)<0) {
    perror("listen error");
    exit(0);
}
//int newsock=(sock,(struct sockaddr*)&address,(socklen_t*)sizeof(address));
char buffer[1024]="asdgsad hello world";
int n1 = send(sock, buffer, 1024, 0);
char buffer2[1024];
int n = recv(sock, buffer2, 1024, 0);
puts(buffer2);
return 0;
}
