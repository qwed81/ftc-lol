#include "system.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// hook functions
__attribute__((ms_abi))
static void* my_CreateFileW(const WCHAR* name, uint32_t access, uint32_t share, void* security, uint32_t creation, uint32_t flags, void* template);

__attribute__((ms_abi))
static void* my_CreateFileA(const char* name, uint32_t access, uint32_t share, void* security, uint32_t creation, uint32_t flags, void* template);

__attribute__((ms_abi))
static uint32_t my_ReadFile(void* handle, void* buffer, uint32_t bytes_to_read, uint32_t* bytes_read, void* lp_overlapped);

static void* log_handle;
static CreateFileWType post_hook_CreateFileW;
static CreateFileAType post_hook_CreateFileA;
static ReadFileType post_hook_ReadFile;

static void* apply_jump_fn_hook(void* new_func, void* addr);

static void log_str(void* log_handle, const char* msg);
static void log_int(void* log_handle, uint64_t val);
static void log_wstr(void* log_handle, const WCHAR* msg);
static void join_str(const char* str1, const char* str2, char* buf, uint32_t buf_len);
static uint32_t str_len(const char* str, uint32_t max);
static bool str_eq(const char* a, const char* b);
static bool wstr_eq(const WCHAR* a, const WCHAR* b);
static bool prefixes_str(const char* prefix, const char* str);

static void* find_mem_pattern(void* begin, uint32_t search_len, const char* pattern);

typedef struct BootstrapData {
    void* arg_kernel32;
    void* arg_lol_module;
    void* arg_swap_return;
    void* arg_seg_table_addr;
    const char* arg_path_root;

    uint64_t var_call_count;
    void* var_expected_return_addr;
    void* var_original_jump_addr;
    void* var_fn_ptr_addr;
} BootstrapData;

typedef struct FileReplaceHeader {
	uint32_t name_str_len;
	uint32_t segment_list_offset;
	uint32_t segent_list_entry_count;

	// the actual string will be the length of
	// name_str_len, however this works as a pointer
	// to the string
	char name_start[4];
} FileReplaceHeader;

#define MOD_SEGMENT 0
#define GAME_SEGMENT 1

typedef struct SegmentReplaceEntry {
	uint32_t segment_type;
	uint32_t start;
	uint32_t len;
	uint32_t data_off;
} SegmentReplaceEntry;

// must be set to locate all of the other os functions
static void* kernel32_addr;
static void* segment_table;
static BootstrapData* bs_data;

__attribute__ ((no_caller_saved_registers, vectorcall))
void init(BootstrapData* data) {
    kernel32_addr = data->arg_kernel32;
    segment_table = data->arg_seg_table_addr;
    bs_data = data;

    char path_buf[1024];
    for (int i = 0; i < 1024; i += 1) {
        path_buf[i] = 0;
    }
    join_str(data->arg_path_root, "/log.txt", path_buf, 1024);

    log_handle = pre_hook_CreateFileA(path_buf,
       GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
       NULL, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL);

    log_str(log_handle, "Log file working");
    log_str(log_handle, "\nlol module at: ");
    log_int(log_handle, (size_t)data->arg_lol_module);

	if (str_eq((char*)segment_table, "seg") == false) {
		log_str(log_handle, "Segment table magic not valid");
		return;
	}

    post_hook_ReadFile = (ReadFileType) apply_jump_fn_hook(my_ReadFile, ReadFileAddr);
    if (post_hook_ReadFile == NULL) {
        log_str(log_handle, "\nCould not hook ReadFile");
        return;
    }

    post_hook_CreateFileA = (CreateFileAType) apply_jump_fn_hook(my_CreateFileA, CreateFileAAddr); 
    if (post_hook_CreateFileA == NULL) {
        log_str(log_handle, "\nCould not hook CreateFileA");
        return;
    }

    post_hook_CreateFileW = (CreateFileWType) apply_jump_fn_hook(my_CreateFileW, CreateFileWAddr); 
    if (post_hook_CreateFileW == NULL) {
        log_str(log_handle, "\nCould not hook CreateFileW");
        return;
    }

    log_str(log_handle, "\ninit successful");
}

// estimated length of the entire LOL module, can be shortened
// if performance becomes a problem
#define SEARCH_LEN 0x0FFFF000

// compiler is not doing what i want when static const char*, not sure why
// but this works :)
#define FILTER_EXPECTED_RETURN "B9 A0 02 00 00 48 89 5C 24 20 E8"
#define FILTER_FN "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 4C 8D 0D"

static uint32_t apply_swap_return_hook() {
    void* er = find_mem_pattern(bs_data->arg_lol_module, SEARCH_LEN, FILTER_EXPECTED_RETURN);
    if (er == NULL) {
        log_str(log_handle, "\nCould not locate expected return");
        return 1;
    }

    bs_data->var_expected_return_addr = er + 0xF; // get the actual value after finding pattern

    void* fn = find_mem_pattern(bs_data->arg_lol_module, SEARCH_LEN, FILTER_FN);
    if (fn == NULL) {
        log_str(log_handle, "\nCould not locate fn ptr");
        return 1;
    }

    int32_t original_jump_offset = *(int32_t*)(fn + 0x3A);
    bs_data->var_original_jump_addr = fn + original_jump_offset + 0x39 + 0x5;

    size_t rip_offset = *(uint32_t*)(fn + 0x3);
    bs_data->var_fn_ptr_addr =  fn + 7 + rip_offset;

    // swap the fn pointer on the stack to my fn
    *(void**)bs_data->var_fn_ptr_addr = bs_data->arg_swap_return;

	log_str(log_handle, "\nfn at: ");
	log_int(log_handle, (size_t)bs_data->var_fn_ptr_addr);

	log_str(log_handle, "\njump original addr: ");
	log_int(log_handle, (size_t)bs_data->var_original_jump_addr);

	log_str(log_handle, "\nexpected return at: ");
	log_int(log_handle, (size_t)bs_data->var_expected_return_addr);

    return 0;
} 

// either returns the header or NULL if it does not exist
static FileReplaceHeader* lookup_file(const char* name) {
	uint32_t num_files = *(uint32_t*)(segment_table + 4);

	// the first header is 8 bytes into the segment table
	FileReplaceHeader* header = (FileReplaceHeader*)(segment_table + 8);
	for (int iter = 0; iter < num_files; iter += 1) {
		if (str_eq(header->name_start, name)) {
			return header;
		}

		// 12 for each of the files, and 1 more for the null terminator
		uint32_t this_header_size = header->name_str_len + 13;
		// take into account padding of the struct
		if (this_header_size % 4 != 0) {
			this_header_size += 4 - this_header_size % 4;
		}
		header = (FileReplaceHeader*)(((char*)header) + this_header_size);
	}

	return NULL;
}

typedef struct MapEntry {
	void* handle;
	FileReplaceHeader* header;
} MapEntry;

#define HEADER_MAP_LEN 512

// the linear probing hashmap
static MapEntry map[HEADER_MAP_LEN] = { 0 }; 

static uint32_t hash_handle(void* handle) {
	return ((size_t)handle >> 4) % HEADER_MAP_LEN;
}

// Will permanently loop if table is filled, but the table should
// never fill so it should be fine. Fix later if it is an issue
static void map_header(void* handle, FileReplaceHeader* header) {
	uint32_t hash = hash_handle(handle);
	while (map[hash].handle != handle) {
		if (map[hash].handle == NULL) {
            map[hash].handle = handle;
            map[hash].header = header;
            break;
		}
		hash = (hash + 1) % HEADER_MAP_LEN;
	}
}

static FileReplaceHeader* get_header(void* handle) {
	uint32_t hash = hash_handle(handle);
	while (map[hash].handle != handle) {
		if (map[hash].handle == NULL) {
			return NULL;
		}
		hash = (hash + 1) % HEADER_MAP_LEN;
	}

	return map[hash].header;
}

static int32_t valid_apply = 0;
__attribute__((ms_abi))
static void* my_CreateFileA(const char* name, uint32_t access, uint32_t share, void* security,
    uint32_t creation, uint32_t flags, void* template) {

    // when the first file that starts with DATA comes, 
    // apply the hook
    if (valid_apply == 0 && prefixes_str("DATA", name)) {
        log_str(log_handle, "\nApplying create file A");
        uint32_t result = apply_swap_return_hook();
        if (result != 0) {
            log_str(log_handle, "\nCould not apply swap hook, retrying on next file");
        } else {
            valid_apply = 1;
        }
    }

	void* handle = post_hook_CreateFileA(name, access, share, security, creation, flags, template);
	if (handle == NULL) {
		return handle;
	}

	FileReplaceHeader* header = lookup_file(name);
	if (header != NULL) {
		map_header(handle, header);
		log_str(log_handle, "\nMapped file: ");
		log_str(log_handle, name);
        log_str(log_handle, ", Handle: ");
        log_int(log_handle, (size_t)handle);
	}

    return handle;
}

static SegmentReplaceEntry* lookup_segment_replace(FileReplaceHeader* header, uint32_t file_off, uint32_t len) {
    // do a binary search on the sorted entries to find the segment to replace
    uint32_t entry_count = header->segent_list_entry_count;
    SegmentReplaceEntry* start = (SegmentReplaceEntry*)(segment_table + header->segment_list_offset);
    for (int i = 0; i < entry_count; i += 1) {
        SegmentReplaceEntry* entry = &start[i];
        if (entry->start == file_off) {
            if (entry->len != len) {
                log_str(log_handle, "\nSame interval start with different lengths. file: ");
                log_str(log_handle, header->name_start);
                log_str(log_handle, " Entry index: ");
                log_int(log_handle, i);
                return NULL;
            }
            return entry;
        }
    }

    return NULL;
}

__attribute__((ms_abi))
static uint32_t my_ReadFile(void* handle, void* buffer, uint32_t bytes_to_read, uint32_t* bytes_read, void* lp_overlapped) {
	FileReplaceHeader* header = get_header(handle);
	// this file does not need to be replaced, give what it asked for
	if (header == NULL) {
    	return post_hook_ReadFile(handle, buffer, bytes_to_read, bytes_read, lp_overlapped);
	}

    // Windows doesn't have GetFilePointer for some reason, but this works
    uint32_t file_off = SetFilePointer(handle, 0, NULL, FILE_CURRENT);
    /*
    log_str(log_handle, "\nReading from mapped file, file pointer: ");
    log_int(log_handle, file_off);
    */
    SegmentReplaceEntry* seg = lookup_segment_replace(header, file_off, bytes_to_read);
    if (seg == NULL) {
        log_str(log_handle, "\nCould not find interval of mapped file: ");
        log_str(log_handle, header->name_start);
        return post_hook_ReadFile(handle, buffer, bytes_to_read, bytes_read, lp_overlapped);
    }

    if (seg->segment_type == GAME_SEGMENT) {
        // read from the game file at a different offset
        SetFilePointer(handle, seg->data_off, NULL, FILE_START);
        uint32_t result = post_hook_ReadFile(handle, buffer, bytes_to_read, bytes_read, lp_overlapped);
        
        // reset the pointer so it can read to the correct spot again
        SetFilePointer(handle, seg->start + seg->len, NULL, FILE_START);
        return result;
    } 
    else if (seg->segment_type == MOD_SEGMENT) {
        char* data = segment_table + seg->data_off;
        /*
        log_str(log_handle, "\nReading from mod: ");
        log_int(log_handle, (size_t)data);
        log_str(log_handle, " len: ");
        log_int(log_handle, (size_t)bytes_to_read);
        */

        // mem copy the data to the from our mod to their buffer
        for (uint32_t i = 0; i < bytes_to_read; i += 1) {
            ((char*)buffer)[i] = data[i];
        }

        // the operation succeeded
        *bytes_read = bytes_to_read;
        SetFilePointer(handle, seg->start + seg->len, NULL, FILE_CURRENT);
        return 1;
    }

    return post_hook_ReadFile(handle, buffer, bytes_to_read, bytes_read, lp_overlapped);
}

// wstr_buf must be 2x the length of str
static void convert_to_wstr(char* str, WCHAR* wstr_buf) {
    uint32_t len = str_len(str, 1000) + 1;
    for (uint32_t i = 0; i < len; i += 1) {
        wstr_buf[i] = str[i];
    }
}

__attribute__((ms_abi))
static void* my_CreateFileW(const WCHAR* name, uint32_t access, uint32_t share, void* security,
    uint32_t creation, uint32_t flags, void* template) {

    // turn off soft repair
    WCHAR buf[1000];
    convert_to_wstr("C:\\Riot Games\\League of Legends\\Game/../SOFT_REPAIR", buf);
    if (wstr_eq(name, buf)) {
        log_str(log_handle, "\nPrevented repairing game files");

        // swap out the name of the file that they are trying to create
        convert_to_wstr("C:\\Riot Games\\League of Legends\\Game/../SOFT_REPAIR_REPLACE", buf);
        return post_hook_CreateFileW(buf, access, share, security, creation, flags, template);
    }

    return post_hook_CreateFileW(name, access, share, security, creation, flags, template);
}

static void* apply_jump_fn_hook(void* new_func, void* addr) {
    uint32_t old_protect = 0;

    uint32_t protect = VirtualProtect(addr, 20, PAGE_EXECUTE_READWRITE, &old_protect);
    if (protect == 0) {
        log_str(log_handle, "\nCould not protect mem RWX, error: ");
        log_int(log_handle, GetLastError());
        return NULL;
    }

    // move their jump down by 5
    void* new_addr = addr + 5;
    // copy the jump instruction 5 bytes down
    *(uint64_t*)(new_addr) = *(uint64_t*)addr;

    // because its using a relative jump, we need to reset the value
    // in the jump to use it's new position
    *(int32_t*)(new_addr + 2) -= 5;

    // change jump instruction to my function
    int32_t offset_jump = (int32_t)((void*)new_func - addr - 5);
    *(uint8_t*)(addr) = 0xE9;
    *(int32_t*)(addr + 1) = offset_jump;

    protect = VirtualProtect(addr, 200, PAGE_EXECUTE_READ, &old_protect);
    if (protect == 0) {
        log_str(log_handle, "\nCould not protect mem RX, error: ");
        log_int(log_handle, GetLastError());
        return NULL;
    }

    return new_addr;
}

static bool prefixes_str(const char* prefix, const char* str) {
    uint32_t i = 0;
    while (true) {
        if (prefix[i] == '\0') {
            return true;
        }

        if (str[i] == '\0' || str[i] != prefix[i]) {
            return false;
        }

        i += 1;
    }
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

static void log_int(void* log_handle, uint64_t val) {
    char buf[19]; // 16 + 2 for 0x + 1 for \0 
    buf[18] = '\0';
    buf[0] = '0';
    buf[1] = 'x';

    for (int i = 17; i > 1; i -= 1) {
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

// joins the two strings together and trucates based on the buf_len
static void join_str(const char* str1, const char* str2, char* buf, uint32_t buf_len) {
    uint32_t str1_len = str_len(str1, buf_len);
    uint32_t str2_len = str_len(str2, buf_len);

    uint32_t i = 0;
    while (i < str1_len) {
        buf[i] = str1[i];
        i += 1;
    }

    uint32_t j = 0;
    while (i < buf_len && j < str2_len) {
        buf[i] = str2[j];
        i += 1;
        j += 1;
    }

    buf[buf_len - 1] = '\0';
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

#define PAGE_LEN 0x1000

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
        log_str(log_handle, "\nCould not interpret pattern");
        return (void*)-1;
    }

    if (PAGE_LEN < PATTERN_BUF_LEN) {
        log_str(log_handle, "\nSegment length is less than pattern length");
        return (void*)-1;
    }

    if ((size_t)start % PAGE_LEN != 0) {
        log_str(log_handle, "\nStart not on page boundary");
        return (void*)-1;
    }

    if (search_len % PAGE_LEN != 0) {
        log_str(log_handle, "\nSearch length not on page boundary");
        return (void*)-1;
    }

    char* current = start;
    while ((void*)current < start + search_len) {

        char mem_buf[PAGE_LEN];
        uint32_t num_read;
        uint32_t can_read = ReadProcessMemory(CURRENT_PROCESS, current, mem_buf, PAGE_LEN, &num_read);

        if (can_read && num_read == PAGE_LEN) {
            uint32_t result = scan_segment(current, PAGE_LEN, buf, skip, buf_len);
            if (result != (uint32_t)-1) {
                return current + result;
            }
        }
        current += PAGE_LEN;
    }

    return NULL;
}


