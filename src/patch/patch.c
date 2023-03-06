#include "system.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define MAX_LOG_LEN 4096
#define MESSAGE_LEN 4096

static void* log_handle;
static CreateFileWType post_hook_CreateFileW;

static void log_str(const char* msg);
static void log_wstr(const wchar_t* msg);
static uint32_t str_len(const char* str, uint32_t max);
static CreateFileWType hook_CreateFileW(void* new_func);

__attribute__((stdcall))
static void* my_func(const wchar_t* name, uint32_t access, uint32_t share, void* security,
    uint32_t creation, uint32_t flags, void* template) {
    
    log_str("we do a little trolling\n");
    log_wstr(name);
    log_str("\n");

    return post_hook_CreateFileW(name, access, share, security, creation, flags, template);
}

__attribute__ ((no_caller_saved_registers, cdecl))
void init(void) {
    log_handle = pre_hook_CreateFileA("C:\\Users\\josh\\Desktop\\log1.txt",
       GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
       NULL, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL);

    log_str("log file working \n");

    post_hook_CreateFileW = hook_CreateFileW(my_func);
    if (post_hook_CreateFileW == NULL) {
        return;
    }

    log_str("sucessfully hooked CreateFileW \n");
}

static CreateFileWType hook_CreateFileW(void* new_func) {
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
    int32_t offset_jmp = (int32_t)(new_func - addr - 5);
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
    while (i < max && wstr[i] != '\0') {
        i += 1;
    }
    return i;
}

static void log_wstr(const wchar_t* msg) {
    uint32_t amt_written = -1;
    uint32_t len = wstr_len(msg, MAX_LOG_LEN / sizeof(wchar_t));

    WriteFile(log_handle, msg, len * sizeof(wchar_t), &amt_written, NULL);
}

static void log_str(const char* msg) {
    uint32_t amt_written = -1;
    uint32_t len = str_len(msg, MAX_LOG_LEN);

    // if the log fails there's nothing to do lol
    WriteFile(log_handle, msg, len, &amt_written, NULL);
}