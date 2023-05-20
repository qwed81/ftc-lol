use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::Deserialize;

pub mod cli;
pub mod patch_loader;
pub mod pkg;
pub mod segment_table;
pub mod wad;

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
    let path =
        env::var("GAME_FOLDER_PATH").expect("GAME_FOLDER_PATH environment variable required");
    PathBuf::from(&path)
}

#[derive(Deserialize)]
struct CodeMeta {
    version: String,
}

static CURRENT_PATCH: Mutex<Option<String>> = Mutex::new(None);

pub fn get_current_patch() -> String {
    let mut lock = CURRENT_PATCH.lock().unwrap();
    match lock.as_deref() {
        Some(str) => str.to_owned(),
        None => {
            // read out from lol's code-metadata.json file and extract the patch
            let mut meta_path = lol_game_folder_path();
            meta_path.push("code-metadata.json");
            let meta = fs::read_to_string(&meta_path).expect("could open current patch folder");
            let meta: CodeMeta = serde_json::from_str(&meta).expect("patch not in expected format");
            let patch = meta.version[0..5].to_owned();
            let ret = patch.clone();
            *lock = Some(patch);
            ret
        }
    }
}
