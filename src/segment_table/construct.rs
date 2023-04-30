use crate::wad::{self, WadEntry};
use memmap2::{Mmap, MmapOptions};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use xxhash_rust::xxh3::Xxh3;

pub fn from_combined_dir(mod_dir: &Path) -> Result<Vec<u8>, ()> {
    // get all files in the mod dir and map them
    let mut paths = Vec::new();
    add_paths_recur(mod_dir, &mut paths);
    let mut new_wads: Vec<Mmap> = Vec::new();
    for path in &paths {
        let file = File::open(path).unwrap();
        let wad = unsafe { MmapOptions::new().map(&file) }.unwrap();
        new_wads.push(wad);
    }

    let mut file_replaces: Vec<FileReplace> = Vec::new();
    for i in 0..new_wads.len() {
        // map the file in the game directory based on the name of the
        // mod file
        let new_wad = &new_wads[i];
        let new_path = &paths[i];
        let old_path = get_equivalent_game_path(new_path, mod_dir);
        let old_wad = File::open(&old_path).unwrap();
        let old_wad = &unsafe { MmapOptions::new().map(&old_wad) }.unwrap();

        let mut entry_map: HashMap<(u64, u64), &WadEntry> = HashMap::new();
        let old_header = wad::read_header(old_wad)?;

        let mut file_replace = FileReplace {
            name: path_to_game_u8(&old_path),
            segments: Vec::new(),
        };

        // add all of the old entries mapped to their name + checksum
        for i in 0..old_header.entry_count {
            let entry = wad::read_entry(old_wad, i)?;
            entry_map.insert((entry.name, entry.checksum), entry);
        }

        let replace_header = wad::read_header(new_wad)?;

        // replace the header with the replace_header
        file_replace.segments.push(SegmentReplace::ModSegment {
            start: wad::HEADER_START,
            data: wad::slice_header(new_wad),
        });

        // replace the entry table with the new entry table
        file_replace.segments.push(SegmentReplace::ModSegment {
            start: wad::ENTRY_TABLE_START,
            data: wad::slice_entry_table(new_wad, replace_header),
        });

        for i in 0..replace_header.entry_count {
            let replace_entry = wad::read_entry(new_wad, i)?;
            match entry_map.remove(&(replace_entry.name, replace_entry.checksum)) {
                // both the old and new file have this entry, load if from game files
                Some(game_entry) => {
                    file_replace.segments.push(SegmentReplace::GameSegment {
                        start: replace_entry.offset,
                        len: replace_entry.len,
                        data_off: game_entry.offset,
                    });
                }
                // only the new file has this entry, so it needs to be added as a mod
                None => {
                    let data = wad::read_entry_data(new_wad, replace_entry)?;
                    assert_eq!(data.len(), replace_entry.len as usize);

                    file_replace.segments.push(SegmentReplace::ModSegment {
                        start: replace_entry.offset,
                        data,
                    })
                }
            }
        }

        file_replace
            .segments
            .sort_by(|a, b| start_of(a).cmp(&start_of(b)));

        file_replaces.push(file_replace);
    }

    Ok(flatten_file_replace(file_replaces))
}

pub fn from_fantome_file(path: &Path) -> Result<Vec<u8>, ()> {
    // index the full game add all of the files to the files vec
    let mut files: Vec<IndexedFile> = Vec::new();
    index_files_recur(&PathBuf::from(crate::LOL_PATH), &mut files).unwrap();

    // go through the entries and add them to the file
    for i in 0..files.len() {
        let file = &mut files[i];
        let header = wad::read_header(&file.data).unwrap();
        for j in 0..header.entry_count {
            let entry = wad::read_entry(&file.data, j).unwrap();
            let name = entry.name;
            file.entries.insert(
                name,
                Entry::GameEntry {
                    entry_index: j,
                    off: entry.offset,
                    len: entry.len,
                },
            );
        }
    }

    // merge all of the entries in the file with the entries in the wad file
    let wad = File::open(path).unwrap();
    let wad = unsafe { MmapOptions::new().map(&wad) }.unwrap();
    for file in &mut files {
        let header = wad::read_header(&wad).unwrap();
        for i in 0..header.entry_count {
            let entry = wad::read_entry(&wad, i).unwrap();
            replace_entry(file, &wad, entry);
        }
    }

    // turn the merged file into a segment replace table
    let mut file_replace: Vec<FileReplace> = Vec::new();
    let mut entry_table_list: Vec<Vec<u8>> = Vec::new();
    let mut header_list: Vec<Vec<u8>> = Vec::new();

    for i in 0..files.len() {
        let file = &files[i];
        if file.entries_modified == false {
            continue;
        }

        let mut segments = Vec::new();

        // get the entries sorted by their names
        let mut entries: Vec<_> = file.entries.iter().collect();
        let entry_count = entries.len();
        entries.sort_by(|(name1, _), (name2, _)| name2.cmp(name1));
        let entries = entries.iter().map(|&(_, entry)| entry);

        let mut header = wad::read_header(&file.data).unwrap().clone();
        let mut hasher = Xxh3::new();
        hasher.update(&wad::slice_header(&file.data)[0..4]);
        for entry in entries.clone() {
            let entry = match entry {
                &Entry::GameEntry {
                    entry_index,
                    off: _,
                    len: _,
                } => wad::read_entry(&file.data, entry_index).unwrap(),
                &Entry::ModEntry { entry, data: _ } => entry,
            };

            hasher.update(&entry.name.to_le_bytes());
            hasher.update(&entry.checksum.to_le_bytes());
        }
        header.signature = hasher.digest128();
        header_list.push(Vec::from(wad::header_as_bytes(&header)));

        // reserve space for the entry table and header
        segments.push(SegmentReplace::ModSegment {
            start: 0,
            data: &[],
        });
        segments.push(SegmentReplace::ModSegment {
            start: 0,
            data: &[],
        });

        let mut entry_table_bytes: Vec<u8> = Vec::new();

        let mut virtual_offset = wad::calc_data_start(entry_count);
        for entry in entries {
            match entry {
                &Entry::GameEntry {
                    entry_index,
                    off,
                    len,
                } => {
                    segments.push(SegmentReplace::GameSegment {
                        start: virtual_offset,
                        len,
                        data_off: off,
                    });

                    let entry = wad::read_entry(&file.data, entry_index).unwrap();
                    let mut new_entry = entry.clone();
                    new_entry.offset = virtual_offset;
                    entry_table_bytes.extend(wad::entry_as_bytes(&new_entry));

                    virtual_offset += len;
                }
                &Entry::ModEntry { entry, data } => {
                    segments.push(SegmentReplace::ModSegment {
                        start: virtual_offset,
                        data,
                    });

                    let mut new_entry = entry.clone();
                    new_entry.offset = virtual_offset;
                    entry_table_bytes.extend(wad::entry_as_bytes(&new_entry));

                    virtual_offset += data.len() as u32;
                }
            }
        }

        file_replace.push(FileReplace {
            name: path_to_game_u8(&file.path),
            segments,
        });

        entry_table_list.push(entry_table_bytes);
    }

    let mut file_replace_index = 0;
    for i in 0..files.len() {
        if files[i].entries_modified == false {
            continue;
        }

        file_replace[file_replace_index].segments[0] = SegmentReplace::ModSegment {
            start: 0,
            data: &header_list[file_replace_index],
        };
        file_replace[file_replace_index].segments[1] = SegmentReplace::ModSegment {
            start: wad::HEADER_LEN as u32,
            data: &entry_table_list[file_replace_index],
        };
        file_replace_index += 1;
    }

    Ok(flatten_file_replace(file_replace))
}

fn replace_entry<'a>(indexed_file: &mut IndexedFile<'a>, wad: &'a [u8], entry: &'a WadEntry) {
    let entry_name = entry.name;
    if indexed_file.entries.contains_key(&entry_name) {
        indexed_file.entries_modified = true;
        indexed_file.entries.insert(
            entry.name,
            Entry::ModEntry {
                entry,
                data: wad::read_entry_data(wad, entry).unwrap(),
            },
        );
    }

    // TODO, detect which entry extra names belong to
    if indexed_file
        .path
        .to_str()
        .unwrap()
        .contains("Nunu.wad.client")
    {
        indexed_file.entries_modified = true;
        indexed_file.entries.insert(
            entry.name,
            Entry::ModEntry {
                entry,
                data: wad::read_entry_data(wad, entry).unwrap(),
            },
        );
    }
}

fn index_files_recur(path: &Path, files: &mut Vec<IndexedFile>) -> io::Result<()> {
    for entry in fs::read_dir(&path)? {
        let entry = entry.unwrap();

        // skip tft
        if entry.file_name().to_str().unwrap().contains("Map21") {
            continue;
        }

        if entry.file_type().unwrap().is_dir() {
            index_files_recur(&entry.path(), files)?;
        } else {
            let path = entry.path();
            let file = File::open(&path)?;
            let mmap = unsafe { MmapOptions::new().map(&file) }?;

            // insert file mapped to path
            files.push(IndexedFile {
                path,
                data: mmap,
                entries: HashMap::new(),
                entries_modified: false,
            });
        }
    }
    Ok(())
}

fn get_equivalent_game_path(mod_path: &Path, mod_root: &Path) -> PathBuf {
    let path_diff = mod_path.strip_prefix(mod_root).unwrap();
    let mut new_path = PathBuf::from(crate::LOL_WAD_PREFIX);
    new_path.push(path_diff);

    new_path
}

fn path_to_game_u8(path: &Path) -> Vec<u8> {
    let path = path.strip_prefix(crate::LOL_WAD_PREFIX).unwrap();
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

fn add_paths_recur(path: &Path, path_list: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(&path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            add_paths_recur(&entry.path(), path_list);
        } else {
            path_list.push(entry.path());
        }
    }
}

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

enum Entry<'a> {
    GameEntry {
        entry_index: u32,
        off: u32,
        len: u32,
    },
    ModEntry {
        entry: &'a WadEntry,
        data: &'a [u8],
    },
}
struct IndexedFile<'a> {
    path: PathBuf,
    data: Mmap,
    entries: HashMap<u64, Entry<'a>>,
    entries_modified: bool,
}

fn start_of(seg: &SegmentReplace) -> u32 {
    match seg {
        &SegmentReplace::GameSegment {
            start,
            len: _,
            data_off: _,
        } => start,
        &SegmentReplace::ModSegment { start, data: _ } => start,
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

// temporary for testing
/*
fn print_file_replace(replace: &FileReplace) {
    println!("{}: ", std::str::from_utf8(&replace.name).unwrap());
    let mut total_len = 0;

    let mut segments = replace.segments.clone();
    segments.sort_by(|x, y| {
        let len = |seg: &SegmentReplace| {
            match seg {
                &SegmentReplace::GameSegment { start: _, len, data_off: _ } => len,
                &SegmentReplace::ModSegment { start: _, data } => data.len() as u32
            }
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
*/
