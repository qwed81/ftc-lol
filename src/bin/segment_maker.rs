use skins::segment_table::SegmentTableBuilder;
use memmap2::MmapOptions;
use std::fs::{File, self};
use std::path::{Path, PathBuf};
use std::env;

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
    let lol_prefix = PathBuf::from("C:/Riot Games/League of Legends/Game/DATA/FINAL/");

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Root directory is needed as first arguemnt");
    }

    let output_name = match args.get(2) {
        Some(output_name) => output_name,
        None => "out.seg"
    };

    let mut file_paths = Vec::new();
    let prefix = &args[1];
    collapse(&PathBuf::from(prefix), &mut file_paths);

    let mut table = SegmentTableBuilder::new();
    let mut game_paths = Vec::new();
    let mut game_wads = Vec::new();
    let mut mod_wads = Vec::new();
    for i in 0..file_paths.len() {
        let rel_path = file_paths[i].strip_prefix(prefix).unwrap();
        let mut game_path = lol_prefix.clone();
        game_path.push(rel_path);

        let game_wad = File::open(&game_path).unwrap();
        let mod_wad = File::open(&file_paths[i]).unwrap();
        game_wads.push(unsafe { MmapOptions::new().map(&game_wad) }.unwrap());
        mod_wads.push(unsafe { MmapOptions::new().map(&mod_wad) }.unwrap());

        game_paths.push(game_path);
    }

    for i in 0..file_paths.len() {
        let game_path = game_paths[i].as_os_str().to_str().unwrap().as_bytes();
        table.add_wad(game_path, &game_wads[i], &mod_wads[i]).unwrap();
    }

    fs::write(output_name, &table.flatten()).unwrap();
}
