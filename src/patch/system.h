#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint16_t WCHAR; 

typedef void* (__stdcall *CreateFileAType)(const char*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*); 
typedef void* (__stdcall *CreateFileWType)(const WCHAR*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*); 
typedef uint32_t (__stdcall *ReadFileType)(void*, void*, uint32_t, uint32_t*, uint32_t*);
typedef uint32_t (__stdcall *ReadProcessMemoryType)(void*, const void*, void*, uint32_t, uint32_t*);

typedef uint32_t (__stdcall *WriteFileType)(void*, const void*, uint32_t, uint32_t*, void*);
typedef uint32_t (__stdcall *VirtualProtectType)(void*, uint32_t, uint32_t, uint32_t*);
typedef uint32_t (__stdcall *GetLastErrorType)();

extern void* kernel32_addr;

#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define CREATE_ALWAYS 0x2
#define FILE_SHARE_READ 0x1
#define FILE_FLAG_WRITE_THROUGH 0x80000000
#define SYNCHRONIZE 0x00100000
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40
#define PAGE_READWRITE 0x04
#define CURRENT_PROCESS ((void*)(-1))

#define CreateFileWAddr (kernel32_addr + 0x23810)
#define CreateFileAAddr (kernel32_addr + 0x23800)
#define WriteFileAddr (kernel32_addr + 0x23C80)
#define VirtualProtectAddr (kernel32_addr + 0x20B90)
#define GetLastErrorAddr (kernel32_addr + 0x1E640)
#define ReadFileAddr (kernel32_addr + 0x23B90)
#define ReadProcessMemoryAddr (kernel32_addr + 0x35830)

#define pre_hook_CreateFileA ((CreateFileAType)CreateFileAAddr)
#define WriteFile ((WriteFileType)WriteFileAddr)
#define VirtualProtect ((VirtualProtectType)VirtualProtectAddr)
#define GetLastError ((GetLastErrorType)GetLastErrorAddr)
#define ReadProcessMemory ((ReadProcessMemoryType)ReadProcessMemoryAddr)
