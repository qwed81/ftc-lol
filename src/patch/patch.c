#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef void* __stdcall (*CreateFileA)(const char*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*); 


#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define OPEN_ALWAYS 0x4

CreateFileA create_file_a = (CreateFileA)0x758D3810;

__attribute__ ((no_caller_saved_registers, cdecl))
void init(void) {

    /*
    void* handle = create_file_a("C:\\Users\\josh\\file.txt\0", GENERIC_READ | GENERIC_WRITE, 0,
       NULL, OPEN_ALWAYS, 0, NULL);

    if (handle == NULL) {
        while (true) {}
    }
    */
}