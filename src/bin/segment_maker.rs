use skins::segment_table::RawSegmentTableBuilder;
use memmap2::MmapOptions;
use std::fs::{File, self};
use std::path::{Path, PathBuf};
use std::env;

fn print_help() {
    println!("usage: [root_dir] [optional: output_name]");
}

fn collapse(path: &Path, names: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(&path).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            collapse(&entry.path(), names);
        } else {
            names.push(entry.path());
        }
    }
}

fn main() {
    let lol_prefix = PathBuf::from(skins::LOL_WAD_PREFIX);

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }

    let output_name = match args.get(2) {
        Some(output_name) => output_name,
        None => "out.seg"
    };

    let mut file_paths = Vec::new();
    let prefix = &args[1];
    collapse(&PathBuf::from(prefix), &mut file_paths);

    let mut table = RawSegmentTableBuilder::new();
    let mut game_paths = Vec::new();
    let mut game_wads = Vec::new();
    let mut mod_wads = Vec::new();
    for i in 0..file_paths.len() {
        let rel_path = file_paths[i].strip_prefix(prefix).unwrap();
        let mut game_path = lol_prefix.clone();
        game_path.push(rel_path);

        println!("calculating: {:?} {:?}", &game_path, &file_paths[i]);
        let game_wad = File::open(&game_path).unwrap();
        let mod_wad = File::open(&file_paths[i]).unwrap();
        game_wads.push(unsafe { MmapOptions::new().map(&game_wad) }.unwrap());
        mod_wads.push(unsafe { MmapOptions::new().map(&mod_wad) }.unwrap());

        game_paths.push(game_path);
    }

    for i in 0..file_paths.len() {
        let without_prefix = game_paths[i].strip_prefix(&lol_prefix).unwrap();
        let game_path = without_prefix.as_os_str().to_str().unwrap().as_bytes();
        
        // replace all \ with / (because it needs to match the game's file requests exactly)
        let replaced: Vec<_> = game_path.iter().map(|&b| match b {
            b'\\' => b'/',
            _ => b
        }).collect();

        // the program is going to exit after making the segment table anyways and this 
        // is a lot easier way to get around the lifetimes
        let replaced: &'static [u8] = Box::leak(Box::new(replaced));

        println!("adding: {}", std::str::from_utf8(game_path).unwrap());
        table.add_wad(&replaced, &game_wads[i], &mod_wads[i]).unwrap();
    }

    fs::write(output_name, &table.flatten()).unwrap();
}
