use std::time::Duration;

use super::{ExLen, ElfOff, MemProt};

pub struct Loader {

}

impl Loader {

    pub fn wait_spawn(process_file_name: &[u8], max_wait: Duration) -> Result<Loader, ()> {
        _ = process_file_name;
        _ = max_wait;
        todo!();
    }

    pub fn from_pid(pid: u32) {
        _ = pid;
        todo!();
    }

    pub fn reserve_mem(&mut self, len: ExLen) -> Result<(), ()> {
        _ = self;
        _ = len;
        todo!();
    }

    pub fn map_segment(&self, offset: ElfOff, len: ExLen) -> Result<(), ()> {
        _ = offset;
        _ = len;
        todo!();
    }

    pub fn mem_write(&self, offset: ElfOff, src: &[u8]) -> Result<(), ()> {
        _ = offset;
        _ = src;
        todo!();
    }

    pub(super) fn mem_protect(&self, offset: ElfOff, len: ExLen, prot: MemProt) -> Result<(), ()> {
        _ = offset;
        _ = len;
        _ = prot;
        todo!();
    }

    pub fn initialize_patch(self, resolve_symbol_offset: impl Fn(&'static str) -> ElfOff) -> Result<(), ()> {
        _ = resolve_symbol_offset;
        todo!();
    }
}
