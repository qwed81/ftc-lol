mod elf_util;

// determine the loader dependent on the target platform
#[cfg(target_os="windows")]
#[cfg(target_arch="x86_64")]
mod windows_loader;
#[cfg(target_os="windows")]
pub use windows_loader::PatchLoader as PatchLoader;

#[cfg(target_os="linux")]
#[cfg(target_arch="x86_64")]
mod linux_loader;
#[cfg(target_os="linux")]
pub use linux_loader::PatchLoader as PatchLoader;

type ExPtr = u64;
type ExLen = u64;
type ElfOff = u32;
type ElfLen = u32;

#[derive(Debug, Clone, Copy)]
enum MemProt {
    R,
    RW,
    RX,
    RWX,
}
