/*
    linux 原来 RAW SOCKET 可以设置下接收到的协议的类型
*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define IN_BUF_SIZE 1500

int main()
{
    int sockfd;
    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP); //直接收  ICMP 包 
    if (sockfd == -1)
    {
        perror("socket");
        return -1;
    }
    while(1) 
    {
        int nbytes;
        char in_buf[IN_BUF_SIZE];
        memset(in_buf, 0x00, IN_BUF_SIZE);
        nbytes = read(sockfd, in_buf, IN_BUF_SIZE - 1);
        if (nbytes > 0) 
        {
            printf("recv %d bytes \n",nbytes);
        }
    }
    return 0;
}
