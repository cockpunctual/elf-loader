#include <sys/stat.h>
#include <stddef.h>
#include <sys/file.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <dlfcn.h>
#include "elf_loader.h"
#include "log.h"

struct elf_module_info info;
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
        LOG_ERR("Get file info failed.");
        return -1;
    }

    file_ptr = malloc(file_info.st_size);
    if (!file_ptr) {
        LOG_ERR("Malloc memory for file content failed.");
        return -1;
    }

    fd = open(file, O_RDONLY);
    if (fd == -1) {
        LOG_ERR("Open %s failed.", file);
        goto error;
    }

    while (len < file_info.st_size) {
        read_byte = read(fd, file_ptr, file_info.st_size);
        if (read_byte == -1) {
            LOG_ERR("Read %s failed.", file);
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

static bool is_dynamic_linked_elf()
{
    return info.hdr->e_type == ET_DYN;
}

static Elf64_Phdr* check_elf_phdr()
{
    Elf64_Phdr* hdr = info.phr;
    Elf64_Phdr* load_addr = NULL;
    Elf64_Addr start, end;
    int idx = 0;

    /* 一般PT_PHDR是包含在第一个可加载段中的，直接找第一个可加载段即可 */
    for (; idx < info.hdr->e_phnum; ++idx) {
        if (hdr[idx].p_type == PT_LOAD) {
            load_addr = info.load_offset + hdr[idx].p_vaddr;
            break;
        }
    }

    /* 校验是否在已加载的内存段中 */
    for (idx = 0; idx < info.hdr->e_phnum; ++idx) {
        if (hdr[idx].p_type != PT_LOAD) {
            continue;
        }
        start = (hdr[idx].p_vaddr + info.load_offset);
        end = start + hdr[idx].p_filesz;
        if (load_addr >= start && load_addr <= end) {
            return load_addr;
        }
    }

    return NULL;
}

static Elf64_Dyn* get_dynamic_sec()
{
    int idx;
    Elf64_Dyn* dyn = NULL;

    for (idx = 0; idx < info.hdr->e_phnum; ++idx) {
        if (info.phr[idx].p_type == PT_DYNAMIC) {
            info.dyn = info.phr[idx].p_vaddr + info.load_offset;
            break;
        }
    }

    dyn = info.dyn;
    return dyn;
}

static bool load_dynamic_section()
{
    Elf64_Dyn* start = info.dyn;

    for (; start->d_tag != DT_NULL; ++start) {
        LOG_DEBUG("d = %p, d[0](tag) = 0x%p d[1](val) = 0x%p", 
            start, (void *)start->d_tag, (void *)start->d_un.d_val);
        switch (start->d_tag)
        {
        case DT_HASH:
            /* code */
            break;
        case DT_GNU_HASH:
            info.gun_hash_param.nbucket = ((uint32_t*)(info.load_offset + start->d_un.d_ptr))[0];
            info.gun_hash_param.symndx = ((uint32_t*)(info.load_offset + start->d_un.d_ptr))[1];
            info.gun_hash_param.maskwords = ((uint32_t*)(info.load_offset + start->d_un.d_ptr))[2];
            info.gun_hash_param.shift2 = ((uint32_t*)(info.load_offset + start->d_un.d_ptr))[3];
            info.gun_hash_param.bloom_filter = (Elf64_Addr*)((info.load_offset + start->d_un.d_ptr + 16));
            info.gun_hash_param.buckets = (uint32_t*)(info.gun_hash_param.bloom_filter + info.gun_hash_param.maskwords);
            info.gun_hash_param.chains = (uint32_t*)(info.gun_hash_param.buckets + info.gun_hash_param.nbucket - info.gun_hash_param.symndx);
            info.gun_hash_param.maskwords--;
            break;
        
        case DT_STRTAB:
            info.strtab = (char*)(info.load_offset + start->d_un.d_ptr);
            break;

        case DT_STRSZ:
            info.strtab_size = start->d_un.d_val;
            break;

        case DT_SYMTAB:
            info.symtab = (Elf64_Sym*)(info.load_offset + start->d_un.d_ptr);
            break;

        case DT_SYMENT:
            if (start->d_un.d_val != sizeof(Elf64_Sym)) {
                LOG_ERR("Wrong DT_SYMENT");
                return false;
            }
            break;

        case DT_PLTREL:
            if (start->d_un.d_val != DT_RELA) {
                LOG_ERR("Wrong DT_PLTREL");
                return false;
            }
            break;

        case DT_JMPREL:
            info.plt_rela = (Elf64_Rela *)(info.load_offset + start->d_un.d_ptr);
            break;

        case DT_PLTRELSZ:
            info.plt_rela_count = start->d_un.d_val / sizeof(Elf64_Rela);
            break;

        case DT_RELA:
            info.rela = (Elf64_Rela*)(info.load_offset + start->d_un.d_ptr);
            break;

        case DT_RELASZ:
            info.rela_count = start->d_un.d_val / sizeof(Elf64_Rela);
            break;

        case DT_RELAENT:
            if (start->d_un.d_val != sizeof(Elf64_Rela)) {
                LOG_ERR("Wrong DT_RELAENT");
                return false;
            }
            break;

        case DT_REL:
            LOG_ERR("unsupported DT_REL in \"%s\"", info.name);
            return false;

        case DT_RELSZ:
            LOG_ERR("unsupported DT_RELSZ in \"%s\"", info.name);
            return false;
        case DT_NEEDED:
            info.needed_count++;
            break;
        default:
            break;
        }
    }

    if (info.strtab == NULL) {
        LOG_ERR("String table is empty");
        return false;
    }

    if (info.symtab == NULL) {
        LOG_ERR("Symbol table is empty");
        return false;
    }

    return true;
}

/**
 * @brief gnu链接器使用的哈希函数
 * @param const char* name
 * @return 字符串的哈希值 
 */
static uint32_t calc_gnu_hash(const char* sym_name)
{
    const char* tmp = sym_name;
    uint32_t hash_val = 5381;

    while (*tmp != 0) {
        hash_val += (hash_val << 5) + *tmp;
        tmp++;
    }
    return hash_val;
}

static bool is_symbol_global_and_define(Elf64_Sym* entry)
{
    if (ELF64_ST_BIND(entry->st_info) == STB_GLOBAL || ELF64_ST_BIND(entry->st_info) == STB_WEAK)
        return entry->st_shndx != SHN_UNDEF;

    return false;
}

/**
 * @brief 通过布隆过滤器和哈希表查找符号
 * @param const char* name
 * @return 返回对应的符号表项
 */
static Elf64_Sym* gnuhash_look_up_symbol(const char* name)
{
    uint32_t chain_idx = 0;
    Elf64_Sym* sym_tab = info.symtab;
    const char* str_tab = info.strtab;
    /* 1. 计算字符串的哈希值 */
    uint32_t hash_val = calc_gnu_hash(name);
    uint32_t h2 = hash_val >> (info.gun_hash_param.shift2);
    /* 2. 计算符号对应的布隆过滤器的下标 */
    uint32_t bloom_filter_mask_len = 64; /* 64位系统的每个布隆过滤器长度是64，32位系统的则为32 */
    uint32_t idx = (hash_val / bloom_filter_mask_len) & info.gun_hash_param.maskwords;
    Elf64_Addr bloom_word = info.gun_hash_param.bloom_filter[idx];

    /* 3. 检查字符串的哈希值是否在布隆过滤器中 */
    if ((1 & (bloom_word >> (hash_val % bloom_filter_mask_len)) & (bloom_word >> (h2 % bloom_filter_mask_len))) == 0) {
        LOG_ERR("Cannot find symbol[%s] in bloom filter.", name);
        return NULL;
    }

    /* 4. 在布隆过滤器初步筛选之后，需要到哈希表中匹配查找 */
    chain_idx = info.gun_hash_param.buckets[hash_val % info.gun_hash_param.nbucket];
    if (chain_idx == 0) {
        LOG_ERR("Cannot find symbol[%s] in hash buckets", name);
        return NULL;
    }

    do {
        Elf64_Sym* entry = sym_tab + chain_idx;
        if (((info.gun_hash_param.chains[chain_idx] ^ hash_val) >> 1) != 0) {
            continue;
        }

        if (strncmp(name, entry->st_name + str_tab, strlen(name))) {
            continue;
        }

        if (is_symbol_global_and_define(entry)) {
            LOG_DEBUG("find symbol: %s", name);
            return entry;
        }

    } while((info.gun_hash_param.chains[chain_idx++] & 1) == 0);

    return NULL;
}

static bool apply_reloc_offset(Elf64_Rela* rela, size_t count)
{
    const char* str_tab = info.strtab;
    char* sym_name;
    Elf64_Sym* sym_tab = info.symtab;
    Elf64_Sym* entry;
    Elf64_Addr reloc, sym_addr, addend;
    uint32_t type, sym;
    /* 1. 遍历所有的重定位项，然后根据类型计算重定位后的地址，并写入到对应的重定位项中 */
    for (uint32_t i = 0; i < count; ++i, rela++) {
        LOG_DEBUG("Processing '%s' relocation at index %zu", info.name, i);
        type = ELF64_R_TYPE(rela->r_info);
        sym = ELF64_R_SYM(rela->r_info);
        reloc = info.load_offset + rela->r_offset;
        addend = rela->r_addend;
        if (sym) {
            sym_name = (char*)(sym_tab[sym].st_name + str_tab);
            entry = gnuhash_look_up_symbol(sym_name);
            if (entry == NULL) {
                sym_addr = (Elf64_Addr)dlsym(NULL, sym_name);
                if (sym_addr) {
                    LOG_DEBUG("dlsym(%s) = 0x%zx", sym_name, sym_addr);
                }
            } else {
                sym_addr = (Elf64_Addr)info.load_offset + entry->st_value;
            }
        }

        /* 根据不同的类型计算重定位地址，并回写到重定位项 */
        switch (type) {
            case R_X86_64_NONE:
                break;
            case R_X86_64_RELATIVE:
                *(uint64_t*)reloc = info.load_offset + addend;
                break;
            case R_X86_64_JUMP_SLOT:
                *(uint64_t*)reloc = sym_addr;
                break;
            case R_X86_64_GLOB_DAT:
                *(uint64_t*)reloc = sym_addr;
                break;
            case R_X86_64_PC32:
                *(uint64_t*)reloc = info.load_offset + addend - reloc;
                break;
            case R_X86_64_32:
                *(uint64_t*)reloc = info.load_offset + addend;
                break;
            case R_X86_64_64:
                *(uint64_t*)reloc = info.load_offset + addend;
                break;
            case R_X86_64_COPY:
                *(uint64_t*)reloc = sym_addr;
                break;
            default:
                LOG_ERR("unknown reloc type %d @ %p (%zu)", type, rela, i);
                return false;
        }
    }

    return true;
}

/**
 * @brief 在dynamic section查找NEEDED类型，并把动态库加载到内存中
 * 
 * @param struct elf_module_info*m 
 * @return true 
 * @return false 
 */
static bool elf_link(struct elf_module_info* m)
{
    Elf64_Dyn* dyn_entry;
    char* name;
    void* handle;

    /* 1. 先把elf或者动态库的依赖库加载到内存中 */
    dyn_entry = info.dyn;
    for (; dyn_entry->d_tag != DT_NULL; ++dyn_entry) {
        if (dyn_entry->d_tag != DT_NEEDED) {
            continue;
        }

        name = dyn_entry->d_un.d_val + info.strtab;
        LOG_DEBUG("load module %s use dlopen()", name);

        if (dlopen(name, RTLD_NOW | RTLD_GLOBAL) == NULL) {
            LOG_ERR("Load shared lib failed, %s", dlerror());
            return false;
        }
    }

    /* 2. 对符号进行重定位 */
    if (info.rela != NULL) {
        apply_reloc_offset(info.rela, info.rela_count);
    }

    if (info.plt_rela) {
        apply_reloc_offset(info.plt_rela, info.plt_rela_count);
    }

    return true;
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
        LOG_ERR("Elf header is null.");
        return false;
    }

    ret = memcmp(info.hdr->e_ident, ELFMAG, SELFMAG);
    if (ret) {
        LOG_ERR("Elf header magic num is invalid.");
        return false;
    }

    if ((info.hdr->e_type != ET_EXEC) && (info.hdr->e_type != ET_DYN)) {
        LOG_ERR("Elf type(%d) is invalid.", ET_DYN);
        return false;
    }

    if (info.hdr->e_version != EV_CURRENT) {
        LOG_ERR("Elf version is invalid.");
        return false;
    }

    if (info.hdr->e_machine != EM_X86_64) {
        LOG_ERR("Elf machine arch is invalid.");
        return false;
    }
    return true;
}

unsigned int look_up_symbol(char* name)
{
    /* 1. 找到symbol section header*/
    Elf64_Shdr* sec_tab_header, *sym_sec, *str_sec;
    int i;
    int j = 0;
    int left = 0, cnt = 0;
    int str_tab_size = 0;
    LOG_DEBUG("Section num: %d", info.hdr->e_shnum);
    sec_tab_header = ((char*)info.hdr + info.hdr->e_shoff);
    for (i = 0; i < info.hdr->e_shnum; ++i) {
        LOG_ERR("find symtable, vaddr: %p", sec_tab_header[i].sh_addr);
        if (sec_tab_header[i].sh_type == SHT_SYMTAB) {
            sym_sec = &sec_tab_header[i];
            break;
        }
    }

    /* 2. 找到string table header*/
    for (i = 0; i < info.hdr->e_shnum; ++i) {
        LOG_DEBUG("find symtable, vaddr: %p", sec_tab_header[i].sh_addr);
        if (sec_tab_header[i].sh_type == SHT_STRTAB) {
            str_sec = &sec_tab_header[i];
            break;
        }
    }

    /* 通过st_name找到对应的字符串和查找的symbol比较 */
    Elf64_Sym* sym_entries = ((char*)info.hdr +  sym_sec->sh_offset);
    int len = 0;
    str_tab_size = str_sec->sh_size;
    char* str_tab = (char*)info.hdr + str_sec->sh_offset;
    LOG_DEBUG("string table size: %x", str_tab_size);
    LOG_DEBUG("idx: %d, sh_type: %x, size: %x", sym_sec->sh_name, sym_sec->sh_offset, sym_sec->sh_size / sizeof(Elf64_Sym));

    LOG_DEBUG("entry cnt: %d", (sym_sec->sh_size / sizeof(Elf64_Sym)));
    while (left < (sym_sec->sh_size / sizeof(Elf64_Sym))) {
        LOG_DEBUG("%d   %s: %p", left, str_tab + sym_entries[left].st_name, sym_entries[left].st_value);
        if (!strcmp(str_tab + sym_entries[left].st_name, name)) {
            LOG_DEBUG("main ptr: %p", sym_entries[left].st_value);
            break;
        }
        left++;
    }

    LOG_ERR("Can find: %s", str_tab + sym_entries[left].st_name);
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
/**
 * @brief 将data、bss、text、rodata映射到内存中
 * 
 */
static void map_seg_to_mem(void)
{
    size_t min_va, max_va;
    get_vaddr_range(&min_va, &max_va);
    size_t mem_size = max_va - min_va ;
    LOG_DEBUG("max va: %x, min va: %x", max_va, min_va);
    size_t idx = 0;
    Elf64_Phdr phr;
    char* bias_ptr;
    ptr = mmap(NULL, mem_size,
        PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (!ptr) {
        LOG_ERR("Mmap segment to mem failed.");
        return;
    }

    bias_ptr = (char*)ptr;
    info.load_offset = ptr - (char*)min_va;
    LOG_DEBUG("base ptr: %x, offset: %x", bias_ptr, info.load_offset);
    info.phr = (Elf64_Phdr*)((char *)info.hdr + info.hdr->e_phoff);
    for (; idx < info.hdr->e_phnum; ++idx) {
        if (info.phr[idx].p_type != PT_LOAD) {
            continue;
        }
        LOG_DEBUG("copy idx: %x, vaddr: %x, file size: %x, mapped addr: %x",
            idx, info.phr[idx].p_vaddr, info.phr[idx].p_filesz, (char*)bias_ptr + info.load_offset);
        memcpy(info.load_offset + info.phr[idx].p_vaddr, ((char*)info.hdr + info.phr[idx].p_offset), info.phr[idx].p_filesz);
        bias_ptr += (info.phr[idx].p_filesz);
    }
}

static void unmmap_elf()
{
    if (info.hdr) {
        free(info.hdr);
    }

    if (ptr) {
        free(ptr);
    }
}

void run_elf_main(char* file)
{
    unsigned int addr;
    Elf64_Sym* sym;
    int (*main)(int argc, char* argv[]);

    load_elf(file);
    if (!verify_ehr_header()) {
        return;
    }

    map_seg_to_mem();
    if (is_dynamic_linked_elf()) {
        get_dynamic_sec();
        check_elf_phdr();
        load_dynamic_section();
        elf_link(&info);
        sym = gnuhash_look_up_symbol("main");
        main = sym->st_value + info.load_offset;
    } else {
        addr = look_up_symbol("main");
        main = addr;
    }

    LOG_DEBUG("%p", main);
    if (main) {
        main(0, NULL);
    }

    unmmap_elf();
}

