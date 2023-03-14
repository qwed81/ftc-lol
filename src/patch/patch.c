#include "system.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MAX_LOG_LEN 4096
#define MESSAGE_LEN 4096

// utility functions
static void log_wstr(const WCHAR* msg);
static uint32_t str_len(const char* str, uint32_t max);
static bool str_cmp(const char* a, const char* b);
static void* apply_jump_fn_hook(void* new_func, void* addr);
static void apply_swap_return_hook();

__attribute__((fastcall))
void log_int(uint32_t val);

__attribute__((fastcall))
void log_str(const char* msg);

// hook functions
__attribute__((stdcall))
static void* my_CreateFileW(const WCHAR* name, uint32_t access, uint32_t share, void* security, uint32_t creation, uint32_t flags, void* template);

__attribute__((stdcall))
static void* my_CreateFileA(const char* name, uint32_t access, uint32_t share, void* security, uint32_t creation, uint32_t flags, void* template);

__attribute__((stdcall))
static uint32_t my_ReadFile(void* handle, void* buffer, uint32_t bytes_to_read, uint32_t* bytes_read, void* lp_overlapped);

static void* log_handle;
static CreateFileWType post_hook_CreateFileW;
static CreateFileAType post_hook_CreateFileA;
static ReadFileType post_hook_ReadFile;

// must be set to locate all of the other os functions
void* kernel32_addr;

// asm functions
void* expected_return_addr;
void* original_jump_addr;
void** fn_ptr_addr; 
uint32_t call_count = 0;

__attribute__((fastcall))
extern void swap_return(void);

// import this symbol from asm, but it is not meant to be used as a call
// it is meant to be used to resolve addresses
// of asm functions at runtime
__attribute__((fastcall))
extern size_t get_runtime_offset(void);
extern void runtime_offset(void);
static void* resolve_runtime_addr(void* addr) {
    return get_runtime_offset() - (size_t)runtime_offset + addr;
}

__attribute__ ((no_caller_saved_registers, fastcall))
void init(void* _kernel32_addr) {
    kernel32_addr = _kernel32_addr;
    
    log_handle = pre_hook_CreateFileA("C:\\Users\\josh\\Desktop\\log1.txt",
       GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
       NULL, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL);

    log_str("log file working \n");

    post_hook_ReadFile = (ReadFileType) apply_jump_fn_hook(my_ReadFile, ReadFileAddr);
    post_hook_CreateFileA = (CreateFileAType) apply_jump_fn_hook(my_CreateFileA, CreateFileAAddr); 
    post_hook_CreateFileW = (CreateFileWType) apply_jump_fn_hook(my_CreateFileW, CreateFileWAddr); 
    apply_swap_return_hook();

    log_str("\nall is well \n");
}

static void apply_swap_return_hook() {
    fn_ptr_addr = (void**)0x0243F368;
    original_jump_addr = (void*)0x01939EC2;
    expected_return_addr = (void*)0x014fefe1;

    void* actual_swap_return = resolve_runtime_addr(swap_return);
    *fn_ptr_addr = actual_swap_return;
} 

static void* file_handle = NULL; 

__attribute__((stdcall))
static uint32_t my_ReadFile(void* handle, void* buffer, uint32_t bytes_to_read, uint32_t* bytes_read, void* lp_overlapped) {
    return post_hook_ReadFile(handle, buffer, bytes_to_read, bytes_read, lp_overlapped);
}

__attribute__((stdcall))
static void* my_CreateFileA(const char* name, uint32_t access, uint32_t share, void* security,
    uint32_t creation, uint32_t flags, void* template) {
    
    log_str("\ncreate file A: ");
    log_str(name);

    if (str_cmp(name, "DATA/FINAL/Champions/Nunu.wad.client")) {
        name = "C:/Users/josh/Desktop/cslol-manager/profiles/Default Profile/DATA/FINAL/Champions/Nunu.wad.client";
    } 
    else if (str_cmp(name, "DATA/FINAL/UI.wad.client")) {
        name = "C:/Users/josh/Desktop/cslol-manager/profiles/Default Profile/DATA/FINAL/UI.wad.client";
    }

    log_str("\ncall count is: ");
    log_int(call_count);

    return post_hook_CreateFileA(name, access, share, security, creation, flags, template);
}

__attribute__((stdcall))
static void* my_CreateFileW(const WCHAR* name, uint32_t access, uint32_t share, void* security,
    uint32_t creation, uint32_t flags, void* template) {
    
    /*
    log_str("\ncreate file W: ");
    log_wstr(name);
    */

    return post_hook_CreateFileW(name, access, share, security, creation, flags, template);
}

static void* apply_jump_fn_hook(void* new_func, void* addr) {
    uint32_t old_protect = 0;

    uint32_t protect = VirtualProtect(addr, 20, PAGE_EXECUTE_READWRITE, &old_protect);
    if (protect == 0) {
        return NULL;
    }

    // move their jump down by 5
    void* new_addr = addr + 5;
    // copy the jump instruction 5 bytes down
    *(uint64_t*)(new_addr) = *(uint64_t*)addr;

    // change their old jump instruction to my function
    int32_t offset_jump = (int32_t)((void*)new_func - addr - 5);
    *(uint8_t*)(addr) = 0xE9;
    *(int32_t*)(addr + 1) = offset_jump;

    protect = VirtualProtect(addr, 200, PAGE_EXECUTE_READ, &old_protect);
    if (protect == 0) {
        return NULL;
    }

    return new_addr;
}

bool str_cmp(const char* a, const char* b) {
    uint32_t i = 0;
    while (true) {
        if (a[i] != b[i]) {
            return false;
        }

        if (a[i] == '\0' || b[i] == '\0') {
            return true;
        }

        i += 1;
    }
}

static uint32_t str_len(const char* str, uint32_t max) {
    uint32_t i = 0;
    while (i < max && str[i] != '\0') {
        i += 1;
    }
    return i;
}

static uint32_t wstr_len(const WCHAR* wstr, uint32_t max) {
    uint32_t i = 0;
    while (i < max && wstr[i] != (WCHAR)0) {
        i += 1;
    }
    return i;
}

__attribute__((fastcall))
void log_str(const char* msg) {
    uint32_t amt_written = -1;
    uint32_t len = str_len(msg, MAX_LOG_LEN);

    // if the log fails there's nothing to do lol
    WriteFile(log_handle, msg, len, &amt_written, NULL);
}

__attribute__((fastcall))
void log_int(uint32_t val) {
    char buf[11]; 
    buf[10] = '\0';
    buf[0] = '0';
    buf[1] = 'x';

    for (int i = 9; i > 1; i -= 1) {
        uint32_t single = val & 0xF;
        char c;
        if (single <= 9) {
            c = single + '0';
        } else {
            c = (single - 10) + 'A';
        }

        val >>= 4;
        buf[i] = c;
    }

    log_str(buf);
}

static void log_wstr(const WCHAR* msg) {
    uint32_t amt_written = -1;
    uint32_t len = wstr_len(msg, MAX_LOG_LEN / sizeof(WCHAR));
    char buf[MAX_LOG_LEN]; 
    for (uint32_t i = 0; i < len; i += 1) {
        if (msg[i] <= 127) {
            buf[i] = msg[i];
        } else {
            buf[i] = '?';
        }
    }

    WriteFile(log_handle, buf, len, &amt_written, NULL);
}
