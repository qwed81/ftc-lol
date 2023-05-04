use std::env;
use std::path::PathBuf;

pub mod patch_loader;
pub mod wad;
pub mod segment_table;
pub mod pkg;

pub fn lol_exe_path() -> PathBuf {
    let mut path = lol_game_folder_path();
    path.push("League of Legends.exe");
    path
}

pub fn lol_wad_path() -> PathBuf {
    let mut path = lol_game_folder_path();
    path.push("DATA");
    path.push("FINAL");
    path
}

pub fn lol_game_folder_path() -> PathBuf {
    let path = env::var("GAME_FOLDER_PATH").expect("GAME_FOLDER_PATH environment variable required");
    PathBuf::from(&path)
}

