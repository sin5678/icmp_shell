// test buffer
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../buffer.h"

char *msg1 = "I am sincoder ";
char *msg2 = " hello world ";

int main(int argc, char **argv)
{
    char null = 0;
    buffer_context ctx;
    char buff[1024];
    int len ;

    buffer_init(&ctx);
    buffer_write(&ctx, msg1, strlen(msg1));
    buffer_write(&ctx, msg2, strlen(msg2));
    buffer_write(&ctx, &null, 1);
    printf("%s\n", buffer_getat(&ctx, 0));
    printf("%s\n", buffer_getat(&ctx, 1));
    memset(buff, 0, sizeof(buff));
    len = buffer_read(&ctx, buff, 5);
    printf("read %d bytes : %s\n", len, buff );
    printf("%s\n", buffer_getat(&ctx, 0));

    memset(buff, 0, sizeof(buff));
    len = buffer_read(&ctx, buff, 1024);
    printf("read %d bytes : %s\n", len, buff );
    printf("%d\n", buffer_getat(&ctx, 0));

    buffer_free(&ctx);
    return 0;
}


