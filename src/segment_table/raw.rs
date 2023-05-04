use super::{FileReplace, SegmentReplace};
use crate::wad::{self, WadEntry};
use memmap2::{Mmap, MmapOptions};
use std::collections::HashMap;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

pub fn from_raw_path(mod_dir: &Path) -> Result<Vec<u8>, ()> {
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
            name: super::path_to_game_u8(&old_path),
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

    Ok(super::flatten_file_replace(file_replaces))
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

fn get_equivalent_game_path(mod_path: &Path, mod_root: &Path) -> PathBuf {
    let path_diff = mod_path.strip_prefix(mod_root).unwrap();
    let mut new_path = PathBuf::from(crate::lol_game_folder_path());
    new_path.push(path_diff);

    new_path
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
