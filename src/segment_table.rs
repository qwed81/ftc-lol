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

use std::collections::HashMap;
use super::wad;

enum SegmentReplace<'a> {
    GameSegment { start: u32, len: u32, data_off: u32 },
    ModSegment { start: u32, data: &'a [u8] }
}

struct FileReplace<'a> {
    name: &'a [u8],
    segments: Vec<SegmentReplace<'a>>
}

pub struct SegmentTableBuilder<'a> {
    files: Vec<FileReplace<'a>>
}

impl<'a> SegmentTableBuilder<'a> {

    pub fn new() -> SegmentTableBuilder<'a> {
        SegmentTableBuilder {
            files: Vec::new()
        }
    }

    pub fn add_wad(&mut self, file_name: &'a [u8], old_file: &[u8], replace_file: &'a [u8]) -> Result<(), ()> {
        let mut entry_map = HashMap::new();
        let old_header = wad::read_header(old_file)?;

        let mut file_replace = FileReplace { 
            name: file_name,
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
        let mut buf = Vec::new();
        buf.extend(&[b's', b'e', b'g', 0]);
        push_u32(&mut buf, self.files.len() as u32);

        let mut file_header_offsets = Vec::with_capacity(self.files.len());

        // write out the file header
        for file in &self.files {
            file_header_offsets.push(buf.len());

            push_u32(&mut buf, file.name.len() as u32);

            // reserve space for the segment data, replace on the 
            // second iteration when we know the location
            reserve_u32(&mut buf, 1);
            push_u32(&mut buf, file.segments.len() as u32);

            buf.extend(file.name);
            buf.push(0); // null terminate the string
            
            // pad until aligned to 4 bytes
            while buf.len() % 4 != 0 {
                buf.push(0);
            }
        }

        let mut entry_table_offsets = Vec::with_capacity(self.files.len());

        // write out the segments
        for i in 0..self.files.len() {
            // on the first time replace header segment_list_offset 
            // with the offset to the start of this table
            let index = file_header_offsets[i] + 4;
            let offset = buf.len();
            set_u32(&mut buf, offset as u32, index);
            entry_table_offsets.push(offset);

            let file = &self.files[i];
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
        for i in 0..self.files.len() {
            let mut segment_index = entry_table_offsets[i];
            for segment in &self.files[i].segments {
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

    pub fn print_stats(&self) {
        for file in &self.files {
            let name = std::str::from_utf8(file.name).unwrap();
            println!("{}:", name); 
            for segment in &file.segments {
                match segment {
                    &SegmentReplace::ModSegment { start, data } => {
                        println!("Replace mod: start: {:x} len: {}", start, data.len());
                    }
                    &SegmentReplace::GameSegment { start, len, data_off } => {
                        println!("Replace game: start: {:x} off: {:x} len: {}", start, data_off, len);
                    }
                }
            }
        }
    }

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

