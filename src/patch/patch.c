#include "system.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

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

static void* apply_jump_fn_hook(void* new_func, void* addr);

static void log_str(void* log_handle, const char* msg);
static void log_int(void* log_handle, uint32_t val);
static void log_wstr(void* log_handle, const WCHAR* msg);
static uint32_t str_len(const char* str, uint32_t max);
static bool str_eq(const char* a, const char* b);

static bool can_read_page(void* addr);
static void* find_mem_pattern(void* begin, uint32_t search_len, const char* pattern);

typedef struct BootstrapData {
    void* arg_kernel32;
    void* arg_lol_module;
    void* arg_swap_return;

    uint32_t var_call_count;
    void* var_expected_return_addr;
    void* var_original_jump_addr;
    void* var_fn_ptr_addr;
} BootstrapData;

static uint32_t apply_swap_return_hook(BootstrapData* data, uint32_t search_len);

// must be set to locate all of the other os functions
static void* kernel32_addr;
static BootstrapData* bs_data;

// compiler is not doing what i want when static const char*, not sure why
// but this works :)
#define FILTER_EXPECTED_RETURN "68 A0 02 00 00 E8 ?? ?? ?? ?? 83 C4 50"
// #define FILTER_FN "74 02 FF E0 8B 44 24 04 85 C0 75 3E"
#define FILTER_FN "A1 ?? ?? ?? ?? 85 C0 74 ?? 3D ?? ?? ?? ?? 74 02 FF E0 8B 44 24"


__attribute__ ((no_caller_saved_registers, fastcall))
void init(BootstrapData* data) {
    kernel32_addr = data->arg_kernel32;
    bs_data = data;

    log_handle = pre_hook_CreateFileA("C:\\Users\\josh\\Desktop\\log1.txt",
       GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
       NULL, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL);

    log_str(log_handle, "log file working");

    log_str(log_handle, "\nlol module at: ");
    log_int(log_handle, (size_t)data->arg_lol_module);

    if (apply_swap_return_hook(data, 4096 * 100000) != 0) {
        return;
    }

    // log the hook values
    log_str(log_handle, "\nfn at: ");
    log_int(log_handle, (size_t)data->var_fn_ptr_addr);
    log_str(log_handle, "\njump original addr: ");
    log_int(log_handle, (size_t)data->var_original_jump_addr);
    log_str(log_handle, "\nexpected return at: ");
    log_int(log_handle, (size_t)data->var_expected_return_addr);

    post_hook_ReadFile = (ReadFileType) apply_jump_fn_hook(my_ReadFile, ReadFileAddr);
    if (post_hook_ReadFile == NULL) {
        log_str(log_handle, "Could not hook ReadFile");
        return;
    }

    post_hook_CreateFileA = (CreateFileAType) apply_jump_fn_hook(my_CreateFileA, CreateFileAAddr); 
    if (post_hook_CreateFileA == NULL) {
        log_str(log_handle, "Could not hook CreateFileA");
        return;
    }

    post_hook_CreateFileW = (CreateFileWType) apply_jump_fn_hook(my_CreateFileW, CreateFileWAddr); 
    if (post_hook_CreateFileW == NULL) {
        log_str(log_handle, "Could not hook CreateFileW");
        return;
    }

}

static uint32_t apply_swap_return_hook(BootstrapData* data, uint32_t search_len) {
    void* er = find_mem_pattern(data->arg_lol_module, search_len, FILTER_EXPECTED_RETURN);
    if (er == NULL) {
        log_str(log_handle, "Could not locate expected return");
        return 1;
    }

    data->var_expected_return_addr = er + 0xA; // get the actual value after finding pattern

    void* fn = find_mem_pattern(data->arg_lol_module, search_len, FILTER_FN);
    if (fn == NULL) {
        log_str(log_handle, "Could not locate fn ptr");
        return 1;
    }

    data->var_original_jump_addr = fn + 0x12;
    data->var_fn_ptr_addr = *(void**)(fn + 0x1); // follow the pointer to get the heap value

    // swap the fn pointer on the stack to my fn
    *(void**)data->var_fn_ptr_addr = data->arg_swap_return;

    return 0;
} 

__attribute__((stdcall))
static uint32_t my_ReadFile(void* handle, void* buffer, uint32_t bytes_to_read, uint32_t* bytes_read, void* lp_overlapped) {
    return post_hook_ReadFile(handle, buffer, bytes_to_read, bytes_read, lp_overlapped);
}

__attribute__((stdcall))
static void* my_CreateFileA(const char* name, uint32_t access, uint32_t share, void* security,
    uint32_t creation, uint32_t flags, void* template) {
    
    log_str(log_handle, "\ncreate file A: ");
    log_str(log_handle, name);

    if (str_eq(name, "DATA/FINAL/Champions/Nunu.wad.client")) {
        name = "C:/Users/josh/Desktop/cslol-manager/profiles/Default Profile/DATA/FINAL/Champions/Nunu.wad.client";
    } 
    else if (str_eq(name, "DATA/FINAL/UI.wad.client")) {
        name = "C:/Users/josh/Desktop/cslol-manager/profiles/Default Profile/DATA/FINAL/UI.wad.client";
    }

    log_str(log_handle, "\ncall count is: ");
    log_int(log_handle, bs_data->var_call_count);

    return post_hook_CreateFileA(name, access, share, security, creation, flags, template);
}

__attribute__((stdcall))
static void* my_CreateFileW(const WCHAR* name, uint32_t access, uint32_t share, void* security,
    uint32_t creation, uint32_t flags, void* template) {

    // log_wstr(log_handle, L"\ncreate file W: ");
    // log_wstr(log_handle, name);

    return post_hook_CreateFileW(name, access, share, security, creation, flags, template);
}

static void* apply_jump_fn_hook(void* new_func, void* addr) {
    uint32_t old_protect = 0;

    uint32_t protect = VirtualProtect(addr, 20, PAGE_EXECUTE_READWRITE, &old_protect);
    if (protect == 0) {
        log_str(log_handle, "\nCould not protect mem, error: ");
        log_int(log_handle, GetLastError());
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

static bool wstr_eq(const WCHAR* a, const WCHAR* b) {
    uint32_t i = 0;
    while (true) {
        if (a[i] != b[i]) {
            return false;
        }
        if (a[i] == (WCHAR)0 || b[i] == (WCHAR)0) {
            return true;
        }
        i += 1;
    }
}

static bool str_eq(const char* a, const char* b) {
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

#define MAX_LOG_LEN 4096
#define MESSAGE_LEN 4096

static void log_str(void* log_handle, const char* msg) {
    uint32_t amt_written = -1;
    uint32_t len = str_len(msg, MAX_LOG_LEN);

    // if the log fails there's nothing to do lol
    WriteFile(log_handle, msg, len, &amt_written, NULL);
}

static void log_int(void* log_handle, uint32_t val) {
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

    log_str(log_handle, buf);
}

static void log_wstr(void* log_handle, const WCHAR* msg) {
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

// returns -1 if there is a ?, -2 if there is an error,
// and return the half byte value otherwise
static int32_t int_from_hex_char(char c) {
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    else if (c >= '0' && c <= '9') {
        return c - '0';
    }
    else if (c == '?') {
        return -1;
    }

    return -2;
}

#define PATTERN_BUF_LEN 70
// the memory pattern must be in the format of "AA ?? F0" null terminated, and must contain
// buf and skip must be of length PATTERN_BUF_LEN
// full bytes (no single characters without space)
static int32_t interpret_pattern(const char* pattern, char* buf, bool* skip, uint32_t* out_len) {
    // should always be less than max_pattern_bytes * 3 so it does not overflow buffer
    const uint32_t max_pattern_str = PATTERN_BUF_LEN * 3 - 3;
    uint32_t actual_str_len = str_len(pattern, max_pattern_str);

    // skip all values that are not specified in the pattern
    for(int i = 0; i < PATTERN_BUF_LEN; i += 1) {
        skip[i] = true;
    }

    // greater than or equal to the max, should fail
    // the string is too long to find
    if (actual_str_len == max_pattern_str || actual_str_len < 2) {
        return -1;
    }

    uint32_t pattern_len = (actual_str_len + 1) / 3;
    for (uint32_t i = 0; i < actual_str_len; i += 3) {
        int32_t a = int_from_hex_char(pattern[i]);
        int32_t b = int_from_hex_char(pattern[i + 1]);
        int32_t byte_index = i / 3;

        // one of the characters is invalid
        if (a == -2 || b == -2) {
            return -1;
        }
        // one of them is a question mark but both of them aren't
        if ((a == -1 || b == -1) && a != b) {
            return -1;
        }

        // if value is -1, it is a question mark, so skip
        skip[byte_index] = a == -1;
        // if they should be skipped it doesn't matter what this field is
        // otherwise figure out what the byte should be
        buf[byte_index] = (a << 4) | b;
    }

    // can not have trailing skips
    if (skip[pattern_len - 1]) {
        return -1;
    }

    *out_len = pattern_len;
    return 0;
}

// reads a page to search for the pattern. If can_read_next, it will attempt to continue
// the pattern into the next page in case of page overlapping patterns
// start must be the start of a page
uint32_t scan_segment(char* mem, uint32_t mem_len, char* buf, bool* skip, uint32_t buf_len) {
    // prevent overflowing the page if we can not read the next
    uint32_t limit = mem_len - buf_len; 
    for (uint32_t i = 0; i < limit; i += 1) {
        uint32_t j = 0;
        while (skip[j] || buf[j] == mem[i + j]) {
            if (j == buf_len) {
                return i;
            }

            j += 1;
        }
    }

    return (uint32_t)-1;
}

#define PAEG_LEN 4096

// returns the beginning of the memory pattern, or NULL if not found in the length
// returns -1 casted to a pointer if an error happens with pattern interpretation 
// requires the parameters of interpret_pattern
// it can not seach across page boundaries
static void* find_mem_pattern(void* start, uint32_t search_len, const char* pattern) {
    char buf[PATTERN_BUF_LEN];
    bool skip[PATTERN_BUF_LEN];
    uint32_t buf_len;

    int32_t result = interpret_pattern(pattern, buf, skip, &buf_len);
    if (result != 0) {
        log_str(log_handle, "Could not interpret pattern");
        return (void*)-1;
    }

    if (PAEG_LEN < PATTERN_BUF_LEN) {
        log_str(log_handle, "Segment length is less than pattern length");
        return (void*)-1;
    }

    if ((size_t)start % PAEG_LEN != 0) {
        log_str(log_handle, "Start not on page boundary");
        return (void*)-1;
    }

    if (search_len % PAEG_LEN != 0) {
        log_str(log_handle, "Search length not on page boundary");
        return (void*)-1;
    }

    char* current = start;
    while ((void*)current < start + search_len) {

        char mem_buf[PAEG_LEN];
        uint32_t num_read;
        uint32_t can_read = ReadProcessMemory(CURRENT_PROCESS, current, mem_buf, sizeof(mem_buf), &num_read);
        if (can_read && num_read == PAEG_LEN) {
            uint32_t result = scan_segment(current, PAEG_LEN, buf, skip, buf_len);
            if (result != (uint32_t)-1) {
                return current + result;
            }
        }
        current += PAEG_LEN;
    }

    return NULL;
}


