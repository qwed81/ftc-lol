#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef void* (__stdcall *CreateFileAType)(const char*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*); 
typedef void* (__stdcall *CreateFileWType)(const wchar_t*, uint32_t, uint32_t, void*, uint32_t, uint32_t, void*); 

typedef uint32_t (__stdcall *WriteFileType)(void*, const void*, uint32_t, uint32_t*, void*);
typedef void* (__stdcall *CreateMutexAType)(void*, uint32_t, const char*);
typedef uint32_t (__stdcall *WaitForSingleObjectType)(void*, uint32_t);
typedef uint32_t (__stdcall *ReleaseMutexType)(void*);
typedef uint32_t (__stdcall *VirtualProtectType)(void*, uint32_t, uint32_t, uint32_t*);


// typedef uint32_t (__stdcall *CloseHandleType)(void*);

#define GENERIC_READ 0x80000000
#define GENERIC_WRITE 0x40000000
#define CREATE_ALWAYS 0x2
#define FILE_SHARE_READ 0x1
#define FILE_FLAG_WRITE_THROUGH 0x80000000
#define SYNCHRONIZE 0x00100000
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40

#define CreateFileWAddr 0x757F3810
#define CreateFileAAddr 0x757F3800
#define WriteFileAddr 0x757F3C80
#define CreateMutexAAddr 0x757F3640
#define WaitForSingleObjectAddr 0x757F37A0
#define ReleaseMutexAddr 0x757f3720
#define VirtualProtectAddr 0x757f0B90

#define WriteFile ((WriteFileType)WriteFileAddr)
#define CreateMutexA ((CreateMutexAType)CreateMutexAAddr)
#define WaitForSingleObject ((WaitForSingleObjectType)WaitForSingleObjectAddr)
#define ReleaseMutex ((ReleaseMutexType)ReleaseMutexAddr)
#define VirtualProtect ((VirtualProtectType)VirtualProtectAddr)
#define pre_hook_CreateFileA ((CreateFileAType)CreateFileAAddr)
