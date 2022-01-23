#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int pwn_me()
{
    char my_buf[RAND_BUF_LEN] = {'\x00'};
    printf("Your buffer is at %p\n", my_buf);
    read(0, my_buf, RAND_READ_LEN);
    return 0;
}

void does_nothing()
{
    char buf[4] = {'\x00'};
    puts("/bin/sh");
    execve("/bin/sleep",NULL,NULL);
    system("sleep 1");
    read(0,buf, sizeof(buf));
}

void give_gadgets()
{
    __asm__("pop %rdx");
    __asm__("ret");
}

void main()
{
    puts("pwn_me:");
    pwn_me();
}