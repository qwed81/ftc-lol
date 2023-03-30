use std::path::Path;
use std::time::Duration;

use skins::patch_loader;

fn main() {
    let lol_path = "C:\\Riot Games\\League of Legends\\Game\\League of Legends.exe";
    //let lol_path = "C:\\Program Files (x86)\\Notepad++\\notepad++.exe";
    //
    let file_path = Path::new("patch");

    patch_loader::load_patch(file_path, lol_path.as_bytes(), Duration::from_millis(100_000)).unwrap();
    println!("done loading!");
}

