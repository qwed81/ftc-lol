use goblin::elf::{Elf, ProgramHeader};
use goblin::elf64::program_header::PT_LOAD;

use super::{ElfOff, MemProt};

pub struct LoadRange {
    pub mem_start: ElfOff,
    pub mem_end: ElfOff
}

pub fn get_sym_offset(elf: &Elf, sym_name: &str) -> Option<ElfOff> {
    for sym in &elf.syms {
        let name = elf.strtab.get_at(sym.st_name);
        match name {
            Some(name) if name == sym_name => {
                return Some(sym.st_value as ElfOff);
            }
            _ => (),
        };
    }

    None
}

pub(super) fn get_protection(header: &ProgramHeader) -> MemProt {
    match (header.is_write(), header.is_executable()) {
        (true, true) => MemProt::RWX,
        (true, false) => MemProt::RW,
        (false, true) => MemProt::RX,
        (false, false) => MemProt::R,
    }
}

pub fn get_load_range(headers: &[ProgramHeader]) -> LoadRange {
    let mem_start: ElfOff = headers
        .iter()
        .filter_map(|h| {
            if h.p_type != PT_LOAD {
                None
            } else {
                Some(h.vm_range().start)
            }
        })
        .min()
        .unwrap()
        .try_into()
        .unwrap();

    let mem_end: ElfOff = headers
        .iter()
        .filter_map(|h| {
            if h.p_type != PT_LOAD {
                None
            } else {
                Some(h.vm_range().end)
            }
        })
        .max()
        .unwrap()
        .try_into()
        .unwrap();

    LoadRange { mem_start, mem_end }
}