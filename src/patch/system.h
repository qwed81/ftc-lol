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

static void* kernel32_addr;

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

#define CreateFileWAddr (kernel32_addr + 0x252C0)
#define CreateFileAAddr (kernel32_addr + 0x252B0)
#define WriteFileAddr (kernel32_addr + 0x25730)
#define ReadFileAddr (kernel32_addr + 0x25640)
#define SetFilePointerAddr (kernel32_addr + 0x256D0)
#define VirtualProtectAddr (kernel32_addr + 0x1C3D0)
#define GetLastErrorAddr (kernel32_addr + 0x161C0)
#define ReadProcessMemoryAddr (kernel32_addr + 0x1CC50)

#define pre_hook_CreateFileA ((CreateFileAType)CreateFileAAddr)
#define WriteFile ((WriteFileType)WriteFileAddr)
#define VirtualProtect ((VirtualProtectType)VirtualProtectAddr)
#define GetLastError ((GetLastErrorType)GetLastErrorAddr)
#define ReadProcessMemory ((ReadProcessMemoryType)ReadProcessMemoryAddr)
#define SetFilePointer ((SetFilePointerType)SetFilePointerAddr)