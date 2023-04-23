// the flattened segment table is optimized for lookup of segments while
// still being serializeable. All numbers are little endian
// flattened segment in the following format:
//
// struct FlattenedSegmentTable {
//      magic: "seg\0",
//      num_files: u32,
//      files: [FileReplaceHeader; num_files],
//
//      // all segments are ordered by their start so they can be binary searched
//      // in the case of asking for a start not directly on the boundary of entries
//      segments: [[SegmentReplaceHeader; segment_list_entry_count]; num_files],
//
//      // the amount of data in the last section is unknown, and all the data
//      // flows together. The SegmentReplaceEntries reference this data
//      blobs: [[u8]] 
//
// }
//
// struct FileReplaceHeader {
//      // pad until size is 4 byte aligned
//      name_str_len: u32,
//      segment_list_offset: u32,
//      segment_list_entry_count: u32,
//      file_name: c_str 
// }
//
// #[repr(u32)]
// enum EntryType {
//      ModSegment = 0,
//      GameSegment = 1
// }
//
// struct SegmentReplaceEntry {
//      type: EntryType
//      start: u32, // start in the phantom file
//      len: u32,
//
//      // either an offset into this file, or file specified by
//      // the file name in FileReplaceHeader depending on EntryType
//      data_off: u32 
// }
//
// 

use std::collections::{HashMap, BTreeMap};
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use memmap2::{Mmap, MmapOptions};
use std::io;
use std::mem;
use super::wad::{self, WadEntry};

enum SegmentReplace<'a> {
    GameSegment { start: u32, len: u32, data_off: u32 },
    ModSegment { start: u32, data: &'a [u8] }
}

struct FileReplace<'a> {
    name: Vec<u8>,
    segments: Vec<SegmentReplace<'a>>
}

struct IndexedFile<'a> {
    path: PathBuf,
    mem: Mmap,
    mod_entries: BTreeMap<usize, (&'a [u8], &'a WadEntry)>
}

pub struct SegmentTableBuilder<'a> {
    files: Vec<IndexedFile<'a>>,
    name_to_file: HashMap<u64, (usize, usize)>, // name to indexed_file, entry_index
}

impl<'a> SegmentTableBuilder<'a> {
    
    pub fn index() -> Result<SegmentTableBuilder<'static>, ()> {
        let mut files = Vec::new();
        let mut name_to_file = HashMap::new();
        
        // recursively add every single file in the directory to our indexed file list
        add_dir(&PathBuf::from(crate::LOL_WAD_PATH), &mut files).unwrap();

        // go through every file and map every entry's name to which file it is in
        // as it's index
        for i in 0..files.len() {
            let file = &files[i];
            let header = wad::read_header(&file.mem).unwrap();
            for j in 0..header.entry_count as usize {
                let entry = wad::read_entry(&file.mem, j).unwrap();
                name_to_file.insert(entry.name, (i, j));
            }
        }

        Ok(SegmentTableBuilder {
            files, name_to_file
        })
    }

    pub fn replace_entry(&mut self, wad: &'a [u8], entry: &'a WadEntry) {
        // if there is no name associated with this entry we are trying
        // to add in the game files, then just skip this entry
        let entry_name = entry.name;
        if let None = self.name_to_file.get(&entry_name) {
            return;
        }

        // add the replace entry to the proper file based on it's name
        let (indexed_file, entry_index) = self.name_to_file[&entry_name];
        self.files[indexed_file].mod_entries.insert(entry_index, (wad, entry));
    }

    // turn the added entries into a list of file replace, so it can be flattened to a
    // FlattenedSegmentTable file
    pub fn flatten(&self) -> Vec<u8> {
        
        // create a vector of FileReplace that can later be flattened
        let mut replace_list = Vec::new();
        
        // this holds all of the entry tables that will be added at the end
        // so their lifetime can outlive the loop and into flatten
        let mut entry_tables: Vec<Vec<u8>> = Vec::new();

        // go through every file
        for i in 0..self.files.len() {
            let file = &self.files[i];
            let header = wad::read_header(&file.mem).unwrap();
            
            // if the file doesn't need to replace anything, then it shouldn't be
            // added to the replace_list
            if file.mod_entries.is_empty() {
                continue;
            }

            // init file_replace
            let mut file_replace = FileReplace {
                // the path might not result in the exact name, (DATA\FINAL instead of DATA/FINAL)
                name: path_to_game_u8(&file.path),
                segments: Vec::new()
            };

            // construct the header that will replace the old header, for now it can just be the same
            // as the previous header, but may need to change in the future 
            file_replace.segments.push(SegmentReplace::ModSegment {
                start: 0, // the header starts at 0
                data: wad::slice_header(&file.mem) // just copy the previous header
            });

            // reserve a location for the entry_table to replace it, for now it is just 0
            file_replace.segments.push(SegmentReplace::ModSegment { 
                start: 0,
                data: &[] 
            });

            // the bytes of the new entry table created by adding all the entries in order
            // this will be held on to until the end of the function so it can be referenced
            // as a mod segment for flattening
            let mut new_entry_table: Vec<u8> = Vec::new();

            let mut mod_entries = file.mod_entries.iter().peekable();
            let entry_count = header.entry_count as usize;
            let mut j = 0;
            let mut start = wad::get_data_start(&file.mem).unwrap();
            while j < entry_count {
                let mut should_next_mod_entries = false;
                // go through every entry. If there is one added to replace the one in the game, then
                // add that as a mod segment, otherwise add it as a game segment
                match mod_entries.peek() {
                    Some(&entry) if *entry.0 == j => {
                        let wad = entry.1.0;
                        
                        // copy the wad entry because we are going to change the offset
                        let wad_data = wad::read_entry_data(&wad, &entry.1.1).unwrap();

                        let mut wad_entry = entry.1.1.clone();
                        wad_entry.offset = start;

                        file_replace.segments.push(SegmentReplace::ModSegment { 
                            // the start is the new location we computed out, and it will be
                            // referenced by the game once we change the entry table as well
                            start, 
                            data: wad_data
                        });
                        
                        // copy the bytes of the wad header to the entry table vector
                        new_entry_table.extend(wad_entry_as_bytes(&wad_entry));

                        should_next_mod_entries = true;
                        start += wad_data.len() as u32;
                    }
                    _ => {
                        // copy the entry so we can change the offset to our start value
                        let mut game_entry = wad::read_entry(&file.mem, j).unwrap().clone();
                        game_entry.offset = start;

                        file_replace.segments.push(SegmentReplace::GameSegment {
                            start,
                            data_off: game_entry.offset,
                            len: game_entry.len
                        });

                        new_entry_table.extend(wad_entry_as_bytes(&game_entry));
                        start += game_entry.len;
                    }
                }

                // for borrow reasons this has to be outside of the match
                if should_next_mod_entries {
                    mod_entries.next();
                }
                j += 1;
            }

            entry_tables.push(new_entry_table);
            replace_list.push(file_replace);
        }

        // replace the data in the mod segment that was reserved now
        // that the entry tables will not be modified
        for i in 0..replace_list.len() {
            let file_replace = &mut replace_list[i];
            file_replace.segments[1] = SegmentReplace::ModSegment { 
                start: wad::ENTRY_TABLE_START,
                data: &entry_tables[i]
            };
        }

        flatten_file_replace(replace_list)
    }

}

fn wad_entry_as_bytes<'a>(entry: &'a WadEntry) -> &'a [u8] {
    // this is safe because it just reinterprets the value as a byte slice
    unsafe { 
        std::slice::from_raw_parts(entry as *const WadEntry as *const u8, mem::size_of::<WadEntry>())
    }
}

fn add_dir(path: &Path, files: &mut Vec<IndexedFile>) -> io::Result<()> {
    for entry in fs::read_dir(&path)? {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            add_dir(&entry.path(), files)?;
        } else {
            let path = entry.path();
            let file = File::open(&path)?;
            println!("opened {:?}", &path);
            let mmap = unsafe { MmapOptions::new().map(&file) }?;
            
            // insert file mapped to path
            files.push(IndexedFile {
                path, mem: mmap, mod_entries: BTreeMap::new()
            });
        }
    }

    Ok(())
}

fn flatten_file_replace(files: Vec<FileReplace>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend(&[b's', b'e', b'g', 0]);
    push_u32(&mut buf, files.len() as u32);

    let mut file_header_offsets = Vec::with_capacity(files.len());

    // write out the file header
    for file in &files {
        file_header_offsets.push(buf.len());

        push_u32(&mut buf, file.name.len() as u32);

        // reserve space for the segment data, replace on the 
        // second iteration when we know the location
        reserve_u32(&mut buf, 1);
        push_u32(&mut buf, file.segments.len() as u32);

        buf.extend(&file.name);
        buf.push(0); // null terminate the string
        
        // pad until aligned to 4 bytes
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
    }

    let mut entry_table_offsets = Vec::with_capacity(files.len());

    // write out the segments
    for i in 0..files.len() {
        // on the first time replace header segment_list_offset 
        // with the offset to the start of this table
        let index = file_header_offsets[i] + 4;
        let offset = buf.len();
        set_u32(&mut buf, offset as u32, index);
        entry_table_offsets.push(offset);

        let file = &files[i];
        for segment in &file.segments {
            match segment {
                &SegmentReplace::ModSegment { start, data } => {
                    push_u32(&mut buf, 0); // the type
                    push_u32(&mut buf, start);
                    push_u32(&mut buf, data.len() as u32);

                    // we don't know wher ethe blob will be, so
                    // reserve the space and overwrite it later
                    reserve_u32(&mut buf, 1);
                },
                &SegmentReplace::GameSegment { start, len, data_off } => {
                    push_u32(&mut buf, 1); // the type
                    push_u32(&mut buf, start);
                    push_u32(&mut buf, len);
                    push_u32(&mut buf, data_off);
                }
            }

        }
    }

    // write out blobs
    for i in 0..files.len() {
        let mut segment_index = entry_table_offsets[i];
        for segment in &files[i].segments {
            // if it is a mod segment, we need to write out the data
            // and set the SegmentReplaceEntry.data_off to the offset
            // of where we are writing the data
            if let &SegmentReplace::ModSegment { start: _, data } = segment {
                let offset = buf.len();
                let data_off_index = segment_index + 12;
                set_u32(&mut buf, offset as u32, data_off_index);

                buf.extend(data);
            }

            // increase by sizeof SegmentReplaceEntry to get
            // the index of the next one
            segment_index += 16;
        }
    }

    buf
}

fn start_of(seg: &SegmentReplace) -> u32 {
    match seg {
        &SegmentReplace::GameSegment { start, len: _, data_off: _ } => start,
        &SegmentReplace::ModSegment { start, data: _ } => start
    }
}

fn reserve_u32(vec: &mut Vec<u8>, amt: usize) {
    for _ in 0..amt {
        vec.extend([0, 0, 0, 0]);
    }
}

fn push_u32(vec: &mut Vec<u8>, val: u32) {
    vec.extend(val.to_le_bytes());
}

fn set_u32(vec: &mut Vec<u8>, val: u32, index: usize) {
    let bytes = val.to_le_bytes();
    for i in 0..4 {
        vec[index + i] = bytes[i];
    }
}


fn path_to_game_u8(path: &Path) -> Vec<u8> {
    let path = path.strip_prefix(crate::LOL_WAD_PREFIX).unwrap();
    let path_u8 = path.as_os_str().to_str().unwrap().as_bytes();

    // replace all \ with / (because it needs to match the game's file requests exactly)
    path_u8.iter().map(|&b| match b {
        b'\\' => b'/',
        _ => b
    }).collect()
}

// makes a segment table by taking in files that need to be replaced with other files.
// this works by taking the entries that occur in the old file and pointing to that instead
// of the new file
pub struct RawSegmentTableBuilder<'a> {
    files: Vec<FileReplace<'a>>
}

impl<'a> RawSegmentTableBuilder<'a> {

    pub fn new() -> RawSegmentTableBuilder<'a> {
        RawSegmentTableBuilder {
            files: Vec::new()
        }
    }

    // add two wad files and it takes the difference between the two of them
    pub fn add_wad(&mut self, file_name: &'a [u8], old_file: &[u8], replace_file: &'a [u8]) -> Result<(), ()> {
        let mut entry_map = HashMap::new();
        let old_header = wad::read_header(old_file)?;

        let mut file_replace = FileReplace { 
            name: Vec::from(file_name),
            segments: Vec::new()
        };
        
        // add all of the old entries mapped to their name + checksum
        for i in 0..(old_header.entry_count as usize) {
            let entry = wad::read_entry(old_file, i)?;
            entry_map.insert((entry.name, entry.checksum), entry);
        }

        let replace_header = wad::read_header(replace_file)?;

        // replace the header with the replace_header
        file_replace.segments.push(SegmentReplace::ModSegment {
            start: wad::HEADER_START,
            data: wad::slice_header(replace_file)
        });

        // replace the entry table with the new entry table
        file_replace.segments.push(SegmentReplace::ModSegment {
            start: wad::ENTRY_TABLE_START,
            data:  wad::slice_entry_table(replace_file, replace_header)
        });
        
        for i in 0..(replace_header.entry_count as usize) {
            let replace_entry = wad::read_entry(replace_file, i)?;
            match entry_map.remove(&(replace_entry.name, replace_entry.checksum)) {
                // both the old and new file have this entry, load if from game files
                Some(game_entry) => {
                    file_replace.segments.push(SegmentReplace::GameSegment {
                        start: replace_entry.offset,
                        len: replace_entry.len,
                        data_off: game_entry.offset
                    });
                }
                // only the new file has this entry, so it needs to be added as a mod
                None => {
                    let data = wad::read_entry_data(replace_file, replace_entry)?;
                    assert_eq!(data.len(), replace_entry.len as usize);

                    file_replace.segments.push(SegmentReplace::ModSegment {
                        start: replace_entry.offset,
                        data
                    })
                }
            }

        }
        
        file_replace.segments.sort_by(|a, b| {
            start_of(a).cmp(&start_of(b))
        });

        self.files.push(file_replace);

        Ok(())
    }

    pub fn flatten(self) -> Vec<u8> {
        flatten_file_replace(self.files)
    }

}
