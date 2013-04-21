/*
  运行在 windows 上的客户端

  使用方法  

  icmp_shell.exe [ip]
  然后弹出一个 窗口 用于执行命令

  搞个对话框真的是多余的 
*/

#include <WinSock2.h>
#include<ws2tcpip.h> 
#include <Windows.h>
#include <stdio.h>
#include <mstcpip.h>
#include "resource.h"
#include "shelldlg.h"

#pragma comment(lib,"ws2_32")

#define dbg_msg(fmt,...) do{\
    printf(##__FUNCTION__##" %d :"##fmt,__LINE__,__VA_ARGS__);\
    }while(0);

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;

#pragma pack(push,1)

struct icmphdr
{
    uint8 type;		/* message type */
    uint8 code;		/* type sub-code */
    uint16 checksum;
    union
    {
        struct
        {
            uint16	id;
            uint16	sequence;
        } echo;			/* echo datagram */
        uint32	gateway;	/* gateway address */
        struct
        {
            uint16	__unused;
            uint16	mtu;
        } frag;			/* path mtu discovery */
    } un;
};

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;


typedef struct _IPHeader		// 20字节的IP头
{
    uint8     iphVerLen;      // 版本号和头长度（各占4位）
    uint8     ipTOS;          // 服务类型 
    uint16    ipLength;       // 封包总长度，即整个IP报的长度
    uint16    ipID;			  // 封包标识，惟一标识发送的每一个数据报
    uint16    ipFlags;	      // 标志
    uint8     ipTTL;	      // 生存时间，就是TTL
    uint8     ipProtocol;     // 协议，可能是TCP、UDP、ICMP等
    uint16    ipChecksum;     // 校验和
    union {
        unsigned int   ipSource;
        ip_address ipSourceByte;
    };
    union {
        unsigned int   ipDestination;
        ip_address ipDestinationByte;
    };
} IPHeader, *PIPHeader; 

#pragma pack(pop)

SOCKET g_sock;


/*
计算 icmp 数据包的 校验和
*/
unsigned short checksum(unsigned short *ptr, int nbytes)
{
    unsigned long sum;
    unsigned short oddbyte, rs;

    sum = 0;
    while(nbytes > 1) 
    {
        sum += *ptr++;
        nbytes -= 2;
    }

    if(nbytes == 1) 
    {
        oddbyte = 0;
        *((unsigned char *) &oddbyte) = *(unsigned char  *)ptr;
        sum += oddbyte;
    }

    sum  = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    rs = ~sum;
    return rs;
}

/*
构建一个回复包 
*/
BOOL  send_icmp_replay_packet(struct icmphdr *request,uint32 ip,char *data,int size)
{
    BOOL ret = FALSE;
    int  packet_size = sizeof(struct icmphdr) + size;
    struct icmphdr *reply_packet = (struct icmphdr *)malloc(packet_size);
    if(NULL != reply_packet)
    {
        char *pdata ;
        sockaddr_in addr;

        memcpy(reply_packet,request,sizeof(struct icmphdr));
        reply_packet->type = 0 ; // reply
        pdata = (char *)(reply_packet + 1);
        memcpy(pdata,data,size);

        reply_packet->checksum = 0;
        reply_packet->checksum = checksum((unsigned short *)reply_packet,packet_size);

        memset(&addr,0,sizeof(sockaddr_in));
        addr.sin_family = AF_INET;
        addr.sin_addr.S_un.S_addr = ip;
        if(sendto(g_sock,(char *)reply_packet,packet_size,0,(sockaddr *)&addr,sizeof(sockaddr_in)) < 1)
        {
            dbg_msg("send packet failed !! \n");
        }
    }
    return ret;
}

BOOL set_socket_recv_all(SOCKET s)
{
    //http://www.okob.net/wp/index.php/2009/04/30/icmp-over-raw-sockets-under-windows-vista/
    /* Run the IOCTL that disables packet filtering on the socket. */
    DWORD tmp, prm = RCVALL_IPLEVEL; /* "RCVALL_IPLEVEL" (Vista SDK) */
    if(WSAIoctl(s, SIO_RCVALL, &prm, sizeof(prm), NULL, 0,
        &tmp, NULL, NULL) == SOCKET_ERROR)
    {
        /* Handle error here */
        return FALSE;
    }
    return TRUE;
}

int main(int argc,char **argv)
{
    WSAData wsa;
    sockaddr_in addr;
    char buff[1500];
    int nbytes = 0;
    int opt = 1;

    int len = sizeof(sockaddr);

    WSAStartup(MAKEWORD(2,2),&wsa);
    g_sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(INVALID_SOCKET == g_sock)
    {
        dbg_msg("create socket failed \n");
        return -1;
    }

    //setsockopt(g_sock,IPPROTO_ICMP, IP_HDRINCL,(char *)&opt,sizeof(int));  //需要操作 ip 头的时候才需要设置
    
    addr.sin_addr.S_un.S_addr = inet_addr("192.168.91.1");
    addr.sin_family = AF_INET;
    addr.sin_port = 0;

    if(SOCKET_ERROR == bind(g_sock,(sockaddr *)&addr,sizeof(sockaddr)))
    {
        dbg_msg("bind failed");
        closesocket(g_sock);
        return -1;
    }
    
    set_socket_recv_all(g_sock);  //  vista 以上的系统必须这样设置下 才能收到 ping request 包。。。

    while((nbytes = recv(g_sock,buff,1500,0)) > 0) //次奥  只能收到 reply 的包
    {
        IPHeader *ip = (IPHeader *)buff;
        int iplen = (ip->iphVerLen & 0xf) * sizeof(unsigned int);
        struct icmphdr *icmp = (struct icmphdr *)((char *)ip + iplen);
        printf("recv %d bytes from %s \n",nbytes,inet_ntoa(*(in_addr *)&ip->ipSource));
        if(0 == icmp->type)
        {
            printf("icmp reply \n");
        }
        else if(8 == icmp->type)
        {
            printf("icmp request \n");
            //收到这个请求的时候 我们应该发送本地的数据  不管有木有 
            send_icmp_replay_packet(icmp,ip->ipSource,"I am sincoder",8);
        }
        else
        {
            printf("unknown type : %d \n",icmp->type);
        }
    }
    dbg_msg("last error : %d \n",GetLastError());
    closesocket(g_sock);
	return 0;
}
