#include <stdio.h>
int add(int num1, int num2)
{
    return num1 + num2;
}

int main(int argc, char* argv[])
{
    int ret;
    ret = add(1, 11);
    char* str = "Hello World!\n";
    // printf("Hello World!\n");
    asm("mov $1, %%rax\n"
        "mov $1, %%rdi\n"
        "mov %0, %%rsi\n"
        "mov $13, %%rdx\n"
        "syscall"
        :
        :"r"(str)
        :"%rax", "%rdi", "%rsi", "%rdx");

    // return 0;
    asm("mov $60, %rax\n"
        "xor %rdi, %rdi\n"
        "syscall");
    return 0;
}