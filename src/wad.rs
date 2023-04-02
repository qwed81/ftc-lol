use std::mem;
use std::slice;

// HeaderV3 defined by lol
#[allow(unused)]
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct WadHeader {
    pub magic: [u8; 2],
    pub major_version: u8,
    pub minor_version: u8,
    pub signature: [u8; 16],
    pub signature_unused: [u8; 240],
    pub checksum: u64,
    pub entry_count: u32  
}

pub const HEADER_LEN: usize = mem::size_of::<WadHeader>();
pub const HEADER_START: u32 = 0;
pub const ENTRY_TABLE_START: u32 = HEADER_LEN as u32;

// Entry 3.1 defined by lol
#[allow(unused)]
#[derive(Debug, Clone, Copy)]
#[repr(C, packed)]
pub struct WadEntry {
    pub name: u64,
    pub offset: u32,
    pub len: u32,
    pub len_decompressed: u32,
    pub entry_type_subchunk_count: u8,
    pub is_duplicate: u8,
    pub subchunk_index: u16,
    pub checksum: u64
}

impl WadEntry {
    pub fn get_entry_type(&self) -> u8 {
        self.entry_type_subchunk_count >> 4
    }

    pub fn get_subchunk_count(&self) -> u8 {
        self.entry_type_subchunk_count & 0xF
    }
}

// returns the bytes for just the header
pub fn slice_header(wad: &[u8]) -> &[u8] {
    &wad[0..HEADER_LEN]
}

// returns the bytes for just the entry table
pub fn slice_entry_table<'a>(wad: &'a [u8], header: &WadHeader) -> &'a [u8] {
    let total_entry_size = header.entry_count as usize * mem::size_of::<WadEntry>();
    &wad[HEADER_LEN..HEADER_LEN + total_entry_size]
}

pub fn read_entry_data<'a>(wad: &'a [u8], entry: &'a WadEntry) -> Result<&'a [u8], ()> {
    if (entry.len + entry.offset) as usize > wad.len() {
        return Err(());
    }

    // make sure the data will not overflow isize when offset (saftey of ptr offset)
    assert!((entry.len as usize + wad.as_ptr() as usize) < isize::MAX as usize);
    Ok(unsafe {
        let data_ptr = wad.as_ptr().offset(entry.len as isize);
        slice::from_raw_parts(data_ptr, entry.len as usize)
    })
}

pub fn read_entry<'a>(wad: &'a [u8], index: usize) -> Result<&'a WadEntry, ()> {
    let offset = HEADER_LEN + index * mem::size_of::<WadEntry>();

    // make sure that the entry addr is in bounds of the file
    if offset + mem::size_of::<WadEntry>() > wad.len() {
        return Err(())
    }

    // assert no wrapping (saftey of ptr offset)
    assert!((offset + wad.as_ptr() as usize) < isize::MAX as usize);
    let entry = unsafe { &*(wad.as_ptr().offset(offset as isize) as *const WadEntry) };
    
    Ok(entry)
}

pub fn read_header<'a>(wad: &'a [u8]) -> Result<&'a WadHeader, ()> {
    if wad.len() < mem::size_of::<WadHeader>() {
        return Err(())
    }
    // this is ptr valid because we ensured the length was correct
    let header = unsafe { &*(wad.as_ptr() as *const WadHeader) };
    if &header.magic != &[b'R', b'W'] {
        return Err(())
    }

    Ok(header)
}
