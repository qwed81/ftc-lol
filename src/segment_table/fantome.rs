use super::{FileReplace, SegmentReplace};
use crate::wad::{self, WadEntry};
use memmap2::{Mmap, MmapOptions};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use xxhash_rust::xxh3::Xxh3;

pub fn from_fantome_wad_list(paths: &Vec<PathBuf>) -> Result<Vec<u8>, ()> {
    // index the full game add all of the files to the files vec
    let mut files: Vec<IndexedFile> = Vec::new();
    index_files_recur(&crate::lol_wad_path(), &mut files).unwrap();

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

    let mut wads: Vec<Mmap> = Vec::new();
    for path in paths {
        let wad = File::open(&path).unwrap();
        let wad = unsafe { MmapOptions::new().map(&wad) }.unwrap();
        wads.push(wad);
    }

    for i in 0..wads.len() {
        let file_name = paths[i].file_name().ok_or(())?;
        let file_name = file_name.to_str().unwrap();

        let wad = &wads[i];
        let header = wad::read_header(&wad).unwrap();

        // merge all of the entries in the file with the entries in the wad file
        for file in &mut files {
            for i in 0..header.entry_count {
                let entry = wad::read_entry(&wad, i).unwrap();
                replace_entry(file, file_name, &wad, entry);
            }
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
        entries.sort_by(|(name1, _), (name2, _)| name1.cmp(name2));

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
        header.checksum = 0;
        header.entry_count = entry_count as u32;

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
            name: super::path_to_game_u8(&file.path),
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

    Ok(super::flatten_file_replace(file_replace))
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

fn replace_entry<'a>(
    indexed_file: &mut IndexedFile<'a>,
    wad_name: &str,
    wad: &'a [u8],
    entry: &'a WadEntry,
) {
    // insert the new entry into all files that contain an entry with
    // the same name
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

    // if there is an extra entry that needs to be added and it does not
    // correspond to any existing entry name, then we add it based on the
    // name of the wad file
    if indexed_file.path.to_str().unwrap().ends_with(wad_name) {
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
