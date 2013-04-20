#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

int read_pipe[2];
int write_pipe[2];

void MyCreateThread(void *(*func)(void *),void *lparam)
{
    pthread_attr_t attr;
    pthread_t  p;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
    pthread_create(&p,&attr,func,lparam);
    pthread_attr_destroy(&attr);
}

void *read_thread(void *lparam)
{
    char cmd[100];
    int bytes = 0;
    while((bytes = read(STDIN_FILENO,cmd,100)) > 0)
    {
        write(write_pipe[1],cmd,bytes);
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    int pid;
    pipe(read_pipe);
    pipe(write_pipe);
    pid = fork();

    if(0 == pid)
    {
        //进入子进程
        //  启动 shell 进程
        close(read_pipe[0]);
        close(write_pipe[1]);
        char *argv[] = {"/bin/sh",NULL};
        char *shell = "/bin/sh";
        dup2(write_pipe[0],STDIN_FILENO); //将输入输出重定向到管道
        dup2(read_pipe[1],STDOUT_FILENO);
        dup2(read_pipe[1],STDERR_FILENO);
        execv(shell,argv);
    }
    else
    {
        char buff;

        close(read_pipe[1]);
        close(write_pipe[0]);
        printf("child process id %d \n",pid);
        write(write_pipe[1],"ls\n",3);
        //启动一个线程来读取
        MyCreateThread(read_thread,NULL);

        while(read(read_pipe[0],&buff,1) > 0)
        {
            putchar(buff);
        }
        waitpid(pid,NULL,0);
        printf("child exit. ..\n");
    }
    return 0;
}