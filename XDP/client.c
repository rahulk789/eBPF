/* 
 * This Program runs a function "myprocess" as a process which connects to two TCP ports 9090, 4040 and echos three strings
 * The function prints it's process id and the source port of client (myprocess)
*/

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#define MAX 80
#define SA struct sockaddr


void myprocess(int sockfd){
    int pid= 0;
    int x=getpid();
    printf("my pid: %d \n",x);
    char buff[MAX];
    int n;
    int t=3;
    while (t--) {
        bzero(buff, sizeof(buff));
        printf("Enter the string : ");
        n = 0;
        while ((buff[n++] = getchar()) != '\n')
            ;
        write(sockfd, buff, sizeof(buff));
        }
}
   
int main()
{
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;
   
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
   
    // assign IP, PORT:4040 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port =htons(4040);
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    // connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");
    /*
    //printing source port
    if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
    	perror("getsockname");
    else
    	printf("port number %d\n", ntohs(sin.sin_port));	 
    */
    
    // myprocess port 4040
    myprocess(sockfd);
    close(sockfd);
    //close
    
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&servaddr, sizeof(servaddr));
   
    // assign IP, PORT:9090 
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port =htons(9090);
    //connect the client socket to server socket
    if (connect(sockfd, (SA*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    
    //printing source port
    /*if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1)
    	perror("getsockname");
    else
    	printf("port number %d\n", ntohs(sin.sin_port));	 
    */
    // myprocess port 9090
    myprocess(sockfd);
    close(sockfd);
    // close connection
}
