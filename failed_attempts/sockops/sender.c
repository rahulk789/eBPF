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
int main() {
int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
int err = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_program, sizeof(bpf_program));
char buffer[1024]="asdgsad hello world";
int n1 = send(sock, buffer, 1024, 0);
return 0;
}
