#include <sys/stat.h>
#include <stddef.h>
#include <sys/file.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <string.h>
#include "elf_loader.h"

struct elf_info info;
size_t load_bias_addr;
/**
 * @brief load elf into memory
 * 
 * @param file 
 * @param buf 
 * @return int 
 */
int load_elf(char* file)
{
    int ret;
    struct stat file_info;
    unsigned char* file_ptr = NULL;
    size_t len = 0, read_byte = 0;
    int fd = -1;

    ret = stat(file, &file_info);
    if (ret != 0) {
        printf("Get file info failed.\n");
        return -1;
    }

    file_ptr = malloc(file_info.st_size);
    if (!file_ptr) {
        printf("Malloc memory for file content failed.\n");
        return -1;
    }

    fd = open(file, O_RDONLY);
    if (fd == -1) {
        printf("Open %s failed.\n", file);
        goto error;
    }

    while (len < file_info.st_size) {
        read_byte = read(fd, file_ptr, file_info.st_size);
        if (read_byte == -1) {
            printf("Read %s failed.\n", file);
            goto error;
        }
        len += read_byte;
    }
    info.len = len;
    info.hdr = (Elf64_Ehdr*)file_ptr;
    info.name = file;
    close(fd);
    return len;

error:
    free(file_ptr);
    close(fd);
    return -1;
}

/**
 * @brief 校验elf文件头格式；成功返回true，失败返回false
 * 
 * @return true 
 * @return false 
 */
static bool verify_ehr_header(void)
{
    int ret;

    if (!info.hdr) {
        printf("Elf header is null.\n");
        return false;
    }

    ret = memcmp(info.hdr->e_ident, ELFMAG, SELFMAG);
    if (ret) {
        printf("Elf header magic num is invalid.\n");
        return false;
    }

    if ((info.hdr->e_type != ET_EXEC) && (info.hdr->e_type != ET_DYN)) {
        printf("Elf type(%d) is invalid.\n", ET_DYN);
        return false;
    }

    if (info.hdr->e_version != EV_CURRENT) {
        printf("Elf version is invalid.\n");
        return false;
    }

    if (info.hdr->e_machine != EM_X86_64) {
        printf("Elf machine arch is invalid.\n");
        return false;
    }
    return true;
}

unsigned int look_up_symbol(char* name)
{
    /* 1. 找到symbol section */
    Elf64_Shdr* sec_tab_header, *sym_sec, *str_sec;
    int i;
    int j = 0;
    int left = 0, cnt = 0;
    int str_tab_size = 0;
    printf("Section num: %d\n", info.hdr->e_shnum);
    sec_tab_header = ((char*)info.hdr + info.hdr->e_shoff);
    for (i = 0; i < info.hdr->e_shnum; ++i) {
        printf("find symtable, vaddr: %p\n", sec_tab_header[i].sh_addr);
        if (sec_tab_header[i].sh_type == SHT_SYMTAB) {
            sym_sec = &sec_tab_header[i];
            break;
        }
    }

    Elf64_Sym* sym_entries = ((char*)info.hdr +  sym_sec->sh_offset);

    for (i = 0; i < info.hdr->e_shnum; ++i) {
        printf("find symtable, vaddr: %p\n", sec_tab_header[i].sh_addr);
        if (sec_tab_header[i].sh_type == SHT_STRTAB) {
            str_sec = &sec_tab_header[i];
            break;
        }
    }
    /* 获取strtab */
    int len = 0;
    str_tab_size = str_sec->sh_size;
    char* str_tab = (char*)info.hdr + str_sec->sh_offset;
    printf("string table size: %x\n", str_tab_size);
    printf("idx: %d, sh_type: %x, size: %x\n", sym_sec->sh_name, sym_sec->sh_offset, sym_sec->sh_size / sizeof(Elf64_Sym));

    printf("entry cnt: %d\n", (sym_sec->sh_size / sizeof(Elf64_Sym)));
    while (left < (sym_sec->sh_size / sizeof(Elf64_Sym))) {
        printf("%d   %s: %p\n", left, str_tab + sym_entries[left].st_name, sym_entries[left].st_value);
        if (!strcmp(str_tab + sym_entries[left].st_name, name)) {
            printf("main ptr: %p\n", sym_entries[left].st_value);
            break;
        }
        left++;
    }
    // printf("cnt: %d, name: %s\n", cnt, str_tab + sym_entries[1448].st_name);
    printf("Can find: %s\n", str_tab + sym_entries[left].st_name);
    return sym_entries[left].st_value;
}

/**
 * @brief 找到data、bss、text、rodata段的最大和最小的虚拟地址
 * 
 * @param min_addr 
 * @param max_addr 
 */
static void get_vaddr_range(size_t* min_addr, size_t* max_addr)
{
    size_t idx = 0;
    size_t min = UINTPTR_MAX, max = 0;
    info.phr = (Elf64_Phdr*)((char*)info.hdr + info.hdr->e_phoff);
    for (; idx < info.hdr->e_phnum; ++idx) {
        if (info.phr[idx].p_type == PT_LOAD) {
            min = min > info.phr[idx].p_vaddr ? info.phr[idx].p_vaddr : min;
            max = max > (info.phr[idx].p_vaddr + info.phr[idx].p_filesz)? max : info.phr[idx].p_vaddr + info.phr[idx].p_filesz;
        }
    }
    *min_addr = min;
    *max_addr = max;
}
char* ptr = NULL;
size_t offset = 0;
/**
 * @brief 将data、bss、text、rodata映射到内存中
 * 
 */
static void map_seg_to_mem(void)
{
    size_t min_va, max_va;
    get_vaddr_range(&min_va, &max_va);
    size_t mem_size = max_va - min_va ;
    printf("max va: %x, min va: %x\n", max_va, min_va);
    size_t idx = 0;
    Elf64_Phdr phr;
    char* bias_ptr;
    ptr = mmap(NULL, mem_size,
        PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!ptr) {
        printf("Mmap segment to mem failed.\n");
        return;
    }

    bias_ptr = (char*)ptr;
    offset = ptr - (char*)min_va;
    printf("base ptr: %x, offset: %x\n", bias_ptr, offset);
    info.phr = (Elf64_Phdr*)((char *)info.hdr + info.hdr->e_phoff);
    for (; idx < info.hdr->e_phnum; ++idx) {
        if (info.phr[idx].p_type != PT_LOAD) {
            continue;
        }
        printf("copy idx: %x, vaddr: %x, file size: %x, mapped addr: %x\n",
            idx, info.phr[idx].p_vaddr, info.phr[idx].p_filesz, (char*)bias_ptr + offset);
        // printf("Header num: %d\n", info.hdr->e_phnum);
        memcpy(offset + info.phr[idx].p_vaddr, ((char*)info.hdr + info.phr[idx].p_offset), info.phr[idx].p_filesz);
        bias_ptr += (info.phr[idx].p_filesz);
    }
}

void run_elf_main(char* file)
{
    unsigned int addr;
    load_elf(file);
    if (!verify_ehr_header()) {
        return;
    }
    map_seg_to_mem();
    addr = look_up_symbol("main");
    int (*main)(int argc, char* argv[]);
    main = addr + offset;
    printf("%p\n", main);
    if (main) {
        main(0, NULL);
    }
}

