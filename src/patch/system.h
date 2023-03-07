#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uint16_t WCHAR; 

typedef void* (__stdcall *CreateFileAType)(const char*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*); 
typedef void* (__stdcall *CreateFileWType)(const WCHAR*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*); 

typedef uint32_t (__stdcall *WriteFileType)(void*, const void*, uint32_t, uint32_t*, void*);
typedef uint32_t (__stdcall *VirtualProtectType)(void*, uint32_t, uint32_t, uint32_t*);

/*
it's possible we will need a mutex in the future (in our hooks)
typedef void* (__stdcall *CreateMutexAType)(void*, uint32_t, const char*);
typedef uint32_t (__stdcall *WaitForSingleObjectType)(void*, uint32_t);
typedef uint32_t (__stdcall *ReleaseMutexType)(void*);
*/

extern void* kernel32_addr;

#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define CREATE_ALWAYS 0x2
#define FILE_SHARE_READ 0x1
#define FILE_FLAG_WRITE_THROUGH 0x80000000
#define SYNCHRONIZE 0x00100000
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40

#define CreateFileWAddr (kernel32_addr + 0x23810)
#define CreateFileAAddr (kernel32_addr + 0x23800)
#define WriteFileAddr (kernel32_addr + 0x23C80)
#define VirtualProtectAddr (kernel32_addr + 0x20B90)

#define WriteFile ((WriteFileType)WriteFileAddr)
#define VirtualProtect ((VirtualProtectType)VirtualProtectAddr)
#define pre_hook_CreateFileA ((CreateFileAType)CreateFileAAddr)
