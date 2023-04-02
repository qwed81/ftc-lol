mod elf_util;

// determine the loader dependent on the target platform
#[cfg(target_os="windows")]
#[cfg(target_arch="x86_64")]
mod windows_loader;
#[cfg(target_os="windows")]

pub use windows_loader::PatchLoader as PatchLoader;
type ExPtr = u32;
type ExLen = u32;
type ElfOff = u32;

#[derive(Debug, Clone, Copy)]
enum MemProt {
    R,
    RW,
    RX,
    RWX,
}

#[cfg(target_os="linux")]
struct PatchLoader;

#[cfg(target_os="linux")]
impl PatchLoader {
    pub async fn wait_can_patch(_name: &[u8]) -> Result<PatchLoader, ()> {
        todo!();
    }

    pub fn freeze_process(&mut self) -> Result<(), ()> { 
        todo!();
    }

    pub async fn load_and_resume(mut self, elf_file: &[u8], segment_table: &[u8]) -> Result<(), ()> {
        todo!();
    }
}


