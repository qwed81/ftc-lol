use std::path::Path;
use std::fs::File;
use std::slice;

use memmap2::MmapOptions;
use goblin::{elf::{Elf, ProgramHeader}, elf64::program_header::PT_LOAD};
use crate::patch_loader::ExLen;

use super::{Loader, MemProt, ExPtr};

fn load_segments(mapped_file: &[u8], elf: &Elf, loader: &mut Loader, mem_start: ExPtr) -> Result<(), ()> {

    // load elf sections
    let mut zero_buffer = Vec::new();
    let mut iter_count = 0;
    for header in &elf.program_headers {
        if header.p_type != PT_LOAD {
            continue;
        }

        let prot = match (header.is_write(), header.is_executable()) {
            (true, true) => MemProt::RWX,
            (true, false) => MemProt::RW,
            (false, true) => MemProt::RX,
            (false, false) => MemProt::R
        };

        println!("loading segment {}", iter_count);
        // the file memory is always less than vm memory range. The
        // difference in the range needs to be zeroed out, as specified by ELF file
        let f_range = header.file_range();
        let m_range = header.vm_range();

        let copy_len: ExLen = f_range.len().try_into().unwrap(); 
        let total_len = m_range.len().try_into().unwrap();
        let vm_offset = (m_range.start - mem_start as usize).try_into().unwrap();
        loader.map_segment(vm_offset, total_len).unwrap();

        // write the actual data from the file into memory
        loader.mem_write(vm_offset, &mapped_file[f_range]).unwrap();

        let left_over_len = (total_len - copy_len) as usize;

        // need to copy over a bunch of zeros to fill out the 
        // gap in memory if the vm size is greater than file size
        if left_over_len > 0 {
            while zero_buffer.len() < left_over_len / 4 + 1 {
                zero_buffer.push(0u64);
            }

            let u8_ptr = zero_buffer.as_ptr() as *const u8;
            let slice = unsafe { slice::from_raw_parts(u8_ptr, left_over_len) };

            loader.mem_write(vm_offset + copy_len, slice).unwrap();
        }

        // enable the protections requested
        loader.mem_protect(vm_offset, total_len, prot).unwrap();

        iter_count += 1;
    }

    Ok(())
}

fn get_load_range(headers: &[ProgramHeader]) -> (ExPtr, ExPtr) {
    let mem_start: ExPtr = headers.iter()
        .filter_map(|h| {
            if h.p_type != PT_LOAD {
                None
            } else {
                Some(h.vm_range().start)
            }
        }).min().unwrap().try_into().unwrap();

    let mem_end: ExPtr = headers.iter()
        .filter_map(|h| {
            if h.p_type != PT_LOAD {
                None
            } else {
                Some(h.vm_range().end)
            }
        }).max().unwrap().try_into().unwrap();
    
    (mem_start, mem_end)
}

// parse the symbol table for the context variable
fn get_addr(elf: &Elf, sym_name: &str) -> ExPtr {
    for sym in &elf.syms {
        let name = elf.strtab.get_at(sym.st_name);
        match name {
            Some(name) if name == sym_name => {
                return sym.st_value as ExPtr;
            } 
            _ => ()
        };
    }

    panic!("the symbol for {} could not be found", sym_name);
}

const RESERVE_ADDR: ExPtr = 0x4020_0000;

pub fn load_patch(file: &Path, mut loader: Loader) -> Result<(), ()> {
    let file = File::open(file).unwrap();

    // elf file mapped into memory
    let mapped_file = unsafe { MmapOptions::new().map(&file).unwrap() };
    let elf = Elf::parse(&mapped_file).unwrap();
    let (mem_start, mem_end) = get_load_range(&elf.program_headers);

    let total_needed = mem_end - mem_start;
    loader.reserve_mem(RESERVE_ADDR, total_needed).unwrap();

    load_segments(&mapped_file, &elf, &mut loader, mem_start).unwrap();
    
    // read the starting address
    let resolve = |sym_name: &str| {
        get_addr(&elf, sym_name)
    };
    loader.initialize_patch(resolve).unwrap();
    
    Ok(())
}




