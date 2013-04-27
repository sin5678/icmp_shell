/*@file wjcdestest.cpp 
WjcDes test 
complied ok with vc++6.0,mingGW 
*/ 
#include <windows.h>
#include <stdio.h> 
#include "des.h"

int main() 
{ 
    char *key = "sincoder";
    char word[64]="mynamexxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxt";/*明文*/
    char buff[65]={0};
    int len ;
    printf("明文=%s\n",word); 
    /*1.设置加密key*/ 
    len = DesEnter(word,buff,strlen(word),key,FALSE);
    buff[64] = 0;
    printf("加密之后,密文=%s  len : %d \n",buff,len); 
    /*3.DES解密*/ 
    DesEnter(buff,word,len,key,TRUE);   //密文长度必须为 8 的倍数 
    printf("解密之后,明文=%s\n",word); 
    return 0; 
} 
/* 
运行结果: 
des demo... 
明文=myname 
加密之后,密文=.S 硲$魮. 
解密之后,明文=myname 
*/ 


