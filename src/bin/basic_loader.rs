use std::path::Path;

use skins::patch_loader;

#[tokio::main]
async fn main() {
    let lol_path = "C:\\Riot Games\\League of Legends\\Game\\League of Legends.exe";
    //let lol_path = "C:\\Program Files (x86)\\Notepad++\\notepad++.exe";
    //
    let file_path = Path::new("target/debug/patch");
    patch_loader::load_patch(file_path, lol_path.as_bytes()).await.unwrap();

    println!("done loading!");
}

