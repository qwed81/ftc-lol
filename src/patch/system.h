#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// system definitions
typedef uint16_t WCHAR; 
typedef struct MODULEINFO {
    void* base;
    uint32_t mod_size;
} MODULEINFO;

typedef __attribute__((ms_abi)) void* (*CreateFileAType)(const char*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*); 
typedef __attribute__((ms_abi)) void* (*CreateFileWType)(const WCHAR*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*); 
typedef __attribute__((ms_abi)) uint32_t (*ReadFileType)(void*, void*, uint32_t, uint32_t*, uint32_t*);
typedef __attribute__((ms_abi)) uint32_t (*ReadProcessMemoryType)(void*, const void*, void*, uint32_t, uint32_t*);
typedef __attribute__((ms_abi)) uint32_t (*WriteFileType)(void*, const void*, uint32_t, uint32_t*, void*);
typedef __attribute__((ms_abi)) uint32_t (*VirtualProtectType)(void*, uint32_t, uint32_t, uint32_t*);
typedef __attribute__((ms_abi)) uint32_t (*GetLastErrorType)();
typedef __attribute__((ms_abi)) uint32_t (*SetFilePointerType)(void*, uint32_t, uint32_t*, uint32_t);

#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define CREATE_ALWAYS 0x2
#define FILE_SHARE_READ 0x1
#define FILE_FLAG_WRITE_THROUGH 0x80000000
#define SYNCHRONIZE 0x00100000
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_READWRITE 0x04
#define LIST_MODULES_32BIT 0x01
#define CURRENT_PROCESS ((void*)(-1))
#define FILE_START 0x0
#define FILE_CURRENT 0x01

// by defining the symbol as __load_{name}, we are requiring
// that the loader gets the actual address of these functions at runtime.
// Because the kernel32 is loaded at the same address of every process on the
// same machine, it does not have to use GetProcAddress in this program,
// but it can do it in the other loader which has much less restrictions
void* __load_CreateFileW;
void* __load_CreateFileA;
void* __load_WriteFile;
void* __load_ReadFile;
void* __load_SetFilePointer;
void* __load_VirtualProtect;
void* __load_GetLastError;
void* __load_ReadProcessMemory;

#define pre_hook_CreateFileA ((CreateFileAType)__load_CreateFileA)
#define WriteFile ((WriteFileType)__load_WriteFile)
#define VirtualProtect ((VirtualProtectType)__load_VirtualProtect)
#define GetLastError ((GetLastErrorType)__load_GetLastError)
#define ReadProcessMemory ((ReadProcessMemoryType)__load_ReadProcessMemory)
#define SetFilePointer ((SetFilePointerType)__load_SetFilePointer)