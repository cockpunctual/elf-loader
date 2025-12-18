#include <elf.h>
#include <stddef.h>
struct elf_info
{
    char* name;
    Elf64_Ehdr* hdr;
    size_t len;
    Elf64_Phdr* phr;
};

void run_elf_main(char* file);