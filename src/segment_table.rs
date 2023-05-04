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

use std::path::Path;

mod fantome;
mod raw;
mod reconstruct;

pub use fantome::from_fantome_wad_list;
pub use raw::from_raw_path;

#[derive(Clone)]
enum SegmentReplace<'a> {
    GameSegment { start: u32, len: u32, data_off: u32 },
    ModSegment { start: u32, data: &'a [u8] },
}

#[derive(Clone)]
struct FileReplace<'a> {
    name: Vec<u8>,
    segments: Vec<SegmentReplace<'a>>,
}

fn flatten_file_replace(files: Vec<FileReplace>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend(&[b's', b'e', b'g', 0]);
    push_u32(&mut buf, files.len() as u32);

    let mut file_header_offsets = Vec::with_capacity(files.len());

    // write out the file header
    for file in &files {
        print_file_replace(file);

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
                }
                &SegmentReplace::GameSegment {
                    start,
                    len,
                    data_off,
                } => {
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
    let path = path.strip_prefix(crate::lol_game_folder_path()).unwrap();
    let path_u8 = path.as_os_str().to_str().unwrap().as_bytes();

    // replace all \ with / (because it needs to match the game's file requests exactly)
    path_u8
        .iter()
        .map(|&b| match b {
            b'\\' => b'/',
            _ => b,
        })
        .collect()
}

// useful for debugging :)
#[allow(unused)]
fn print_file_replace(replace: &FileReplace) {
    println!("{}: ", std::str::from_utf8(&replace.name).unwrap());
    let mut total_len = 0;

    let mut segments = replace.segments.clone();
    segments.sort_by(|x, y| {
        let len = |seg: &SegmentReplace| match seg {
            &SegmentReplace::GameSegment {
                start: _,
                len,
                data_off: _,
            } => len,
            &SegmentReplace::ModSegment { start: _, data } => data.len() as u32,
        };
        len(x).cmp(&len(y))
    });

    for replace in &segments {
        match replace {
            SegmentReplace::GameSegment {
                start,
                len,
                data_off: _,
            } => {
                // println!("GameSegment start: {}, len: {}", start, len);
                total_len += *len;
            }
            SegmentReplace::ModSegment { start, data } => {
                println!("ModSegment: start: {}, len: {}", start, data.len());
                total_len += data.len() as u32;
            }
        }
    }

    println!("total len is: {}", total_len);
}
