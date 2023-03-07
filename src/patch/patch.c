#include "system.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MAX_LOG_LEN 4096
#define MESSAGE_LEN 4096

// utility functions
static void log_str(const char* msg);
static void log_wstr(const wchar_t* msg);
static uint32_t str_len(const char* str, uint32_t max);

// hook setups
static CreateFileWType hook_CreateFileW(CreateFileWType new_func);

// hook functions
__attribute__((stdcall))
static void* my_CreateFileW(const wchar_t* name, uint32_t access, uint32_t share, void* security, uint32_t creation, uint32_t flags, void* template);

static void* log_handle;
static CreateFileWType post_hook_CreateFileW;

// must be set to locate all of the other os functions
void* kernel32_addr;

__attribute__ ((no_caller_saved_registers, fastcall))
void init(void* _kernel32_addr) {
    kernel32_addr = _kernel32_addr;
    
    log_handle = pre_hook_CreateFileA("C:\\Users\\josh\\Desktop\\log1.txt",
       GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
       NULL, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL);

    log_str("log file working \n");

    post_hook_CreateFileW = hook_CreateFileW(my_CreateFileW);
    if (post_hook_CreateFileW == NULL) {
        return;
    }

    log_str("sucessfully hooked CreateFileW \n");
}

__attribute__((stdcall))
static void* my_CreateFileW(const wchar_t* name, uint32_t access, uint32_t share, void* security,
    uint32_t creation, uint32_t flags, void* template) {
    
    log_str("\ncreate file w: \n");
    // log_wstr(name);

    return post_hook_CreateFileW(name, access, share, security, creation, flags, template);
}

static CreateFileWType hook_CreateFileW(CreateFileWType new_func) {
    void* addr = (void*)CreateFileWAddr;
    uint32_t old_protect = 0;

    uint32_t protect = VirtualProtect(addr, 200, PAGE_EXECUTE_READWRITE, &old_protect);
    if (protect == 0) {
        log_str("hook_CreateFileW could not change to rwx \n");
        return NULL;
    }

    // move their jump down by 5
    void* new_addr = addr + 5;
    // copy the jmp instruction 5 bytes down
    *(uint64_t*)(new_addr) = *(uint64_t*)addr;

    // change their old jump instruction to my function
    int32_t offset_jmp = (int32_t)((void*)new_func - addr - 5);
    *(uint8_t*)(addr) = 0xE9;
    *(int32_t*)(addr + 1) = offset_jmp;

    protect = VirtualProtect(addr, 200, PAGE_EXECUTE_READ, &old_protect);

    if (protect == 0) {
        log_str("hook_CreateFileW could not change to rx \n");
        return NULL;
    }

    return (CreateFileWType)new_addr;
}

static uint32_t str_len(const char* str, uint32_t max) {
    uint32_t i = 0;
    while (i < max && str[i] != '\0') {
        i += 1;
    }
    return i;
}

static uint32_t wstr_len(const wchar_t* wstr, uint32_t max) {
    uint32_t i = 0;
    while (i < max && wstr[i] != (wchar_t)0) {
        i += 1;
    }
    return i;
}

static void log_wstr(const wchar_t* msg) {
    uint32_t amt_written = -1;
    uint32_t len = wstr_len(msg, MAX_LOG_LEN / sizeof(wchar_t));
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

static void log_str(const char* msg) {
    uint32_t amt_written = -1;
    uint32_t len = str_len(msg, MAX_LOG_LEN);

    // if the log fails there's nothing to do lol
    WriteFile(log_handle, msg, len, &amt_written, NULL);
}