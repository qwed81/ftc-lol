// this should be changed when more targets are supported, gets rid
// of unused warnings for now
#[cfg(target_os="windows")]
mod elf_util;

// determine the loader dependent on the target platform
#[cfg(target_os="windows")]
mod windows_loader;
#[cfg(target_os="windows")]
pub use windows_loader::PatchLoader as PatchLoader;

#[cfg(target_os="linux")]
#[cfg(target_arch="x86_64")]
mod linux_loader;
#[cfg(target_os="linux")]
pub use linux_loader::PatchLoader as PatchLoader;

#[derive(Debug)]
pub struct LoadError {
    pub message: String,
    pub code: Option<u32>
}

#[allow(unused)]
type ExPtr = u64;

#[allow(unused)]
type ExLen = u64;

#[allow(unused)]
type ElfOff = u32;

#[allow(unused)]
type ElfLen = u32;

#[derive(Debug, Clone, Copy)]
#[allow(unused)]
enum MemProt {
    R,
    RW,
    RX,
    RWX,
}
