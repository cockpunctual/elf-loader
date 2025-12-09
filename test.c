#include <stdio.h>
int add(int num1, int num2)
{
    return num1 + num2;
}

int main(int argc, char* argv[])
{
    int ret;
    ret = add(1, 11);
    printf("ret = %d\n", ret);
    return 0;
}