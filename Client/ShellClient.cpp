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
#include "resource.h"
#include "shelldlg.h"

#pragma comment(lib,"ws2_32")

#define dbg_msg(fmt,...) do{\
    printf(##__FUNCTION__##" %d :"##fmt,__LINE__,__VA_ARGS__);\
    }while(0);

SOCKET g_sock;

int main(int argc,char **argv)
{
    WSAData wsa;
    sockaddr_in addr;
    char buff[1500];
    int nbytes = 0;
    int opt = 1;

    WSAStartup(MAKEWORD(2,2),&wsa);
    g_sock = socket(AF_INET,SOCK_RAW,IPPROTO_ICMP);
    if(INVALID_SOCKET == g_sock)
    {
        dbg_msg("create socket failed \n");
        return -1;
    }

    //
    //setsockopt(g_sock,IPPROTO_IP, IP_HDRINCL,(char *)&opt,sizeof(int));

    addr.sin_addr.S_un.S_addr = 0;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;

    if(SOCKET_ERROR == bind(g_sock,(sockaddr *)&addr,sizeof(sockaddr)))
    {
        dbg_msg("bind failed");
        closesocket(g_sock);
        return -1;
    }

    while((nbytes = recv(g_sock,buff,1500,0)) > 0)
    {
        printf("recv %d bytes \n",nbytes);
    }
    dbg_msg("last error : %d \n",GetLastError());
    closesocket(g_sock);
	return 0;
}
