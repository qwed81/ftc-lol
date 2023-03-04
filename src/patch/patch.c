#include <stdint.h>

typedef void* (__attribute__((stdcall)) *CreateFileW)(const wchar_t*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*); 

#define GENERIC_READ 0x80000000

CreateFileW create_file_w = (CreateFileW)0x758D3810;

__attribute__ ((no_caller_saved_registers, fastcall))
void init(void) {
    create_file_w(L"C:\\Users\\josh\\Desktop\\test.txt",
        GENERIC_READ, 0, NULL, 2, 0x80, NULL);
}