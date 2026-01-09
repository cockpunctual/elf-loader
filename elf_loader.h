#include <elf.h>
#include <stddef.h>
#include <stdbool.h>
#include "list.h"
struct gnu_hash {  
    uint32_t nbucket;  // 哈希桶的数量
    uint32_t symndx;  
    uint32_t maskwords;  // 布隆过滤器的大小，该值必须是2的幂
    uint32_t shift2;  
    Elf64_Addr* bloom_filter;// 32位elf每个元素32bit uint32_t，64位elf每个元素64bit uint64_t  
    uint32_t* buckets;  
    uint32_t* chains;  
};

struct elf_module_info
{
    char* name;
    size_t len; /* ELF文件的长度（大小） */
    bool dynamic_linked; /* 是否为动态链接的ELF */
    Elf64_Ehdr* hdr;
    Elf64_Phdr* phr;
    Elf64_Dyn* dyn;
    Elf64_Addr load_offset;
    struct gnu_hash gun_hash_param;
    const char *strtab;
    size_t strtab_size;
    Elf64_Sym *symtab;
    Elf64_Rela *plt_rela;
    size_t plt_rela_count;
    Elf64_Rela *rela;
    size_t rela_count;
    size_t needed_count;
    struct list_head dep_mod_list;
};

void run_elf_main(char* file);