use goblin::elf::{Elf, ProgramHeader};
use goblin::elf64::program_header::PT_LOAD;

use super::{ElfOff, MemProt};

pub struct LoadRange {
    pub elf_start: ElfOff,
    pub elf_end: ElfOff
}

pub fn get_sym_offset(elf: &Elf, sym_name: &str) -> Option<ElfOff> {
    for sym in &elf.syms {
        let name = elf.strtab.get_at(sym.st_name).unwrap();
        if name == sym_name {
            return Some(sym.st_value as ElfOff);
        }
    }

    None
}

pub fn get_load_symbols<'a>(elf: &'a Elf) -> Vec<(&'a str, ElfOff)> {
    let mut vals = Vec::new();
    for sym in &elf.syms {
        let name = elf.strtab.get_at(sym.st_name).unwrap();
        if name.starts_with("__load_") {
            vals.push((name.strip_prefix("__load_").unwrap(), sym.st_value as ElfOff));
        }
    }

    vals
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

    LoadRange { elf_start: mem_start, elf_end: mem_end }
}