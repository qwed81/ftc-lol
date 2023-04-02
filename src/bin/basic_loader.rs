use std::fs::File;

use memmap2::MmapOptions;
use skins::patch_loader::PatchLoader;

#[tokio::main]
async fn main() {
    let lol_path = "C:\\Riot Games\\League of Legends\\Game\\League of Legends.exe";
    //let lol_path = "C:\\Program Files (x86)\\Notepad++\\notepad++.exe";
    //

    let mut loader = PatchLoader::wait_can_patch(lol_path.as_bytes()).await.unwrap();
    loader.freeze_process().unwrap();

    let segment_table = &[0];
    let elf_file = File::open("target/debug/patch").unwrap();
    let elf_file = unsafe { MmapOptions::new().map(&elf_file) }.unwrap();

    loader.load_and_resume(&elf_file, segment_table).unwrap();

    println!("done loading!");
}

