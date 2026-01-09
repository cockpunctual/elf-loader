#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "elf_loader.h"
int main()
{
    run_elf_main("./test.so");
    return 0;
}