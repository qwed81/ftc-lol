use std::fs::File;

use memmap2::MmapOptions;
use skins::segment_table::SegmentTableBuilder;
use skins::patch_loader::PatchLoader;

#[tokio::main]
async fn main() {
    let lol_path = "C:\\Riot Games\\League of Legends\\Game\\League of Legends.exe";
    // let lol_path = "C:\\Program Files\\Notepad++\\notepad++.exe";

    let elf_file = File::open("target/debug/patch").unwrap();
    let elf_file = unsafe { MmapOptions::new().map(&elf_file) }.unwrap();

    let path1 = "C:/Riot Games/League of Legends/Game/DATA/FINAL/Champions/Nunu.wad.client";
    let path2 = "C:/Users/josh/Desktop/cslol-manager/profiles/Default Profile/DATA/FINAL/Champions/Nunu.wad.client";
    let path3 = "C:/Riot Games/League of Legends/Game/DATA/FINAL/UI.wad.client";
    let path4 = "C:/Users/josh/Desktop/cslol-manager/profiles/Default Profile/DATA/FINAL/UI.wad.client";
    let path1_sub = "DATA/FINAL/Champions/Nunu.wad.client";
    let path3_sub = "DATA/FINAL/UI.wad.client";

    let wad1 = File::open(path1).unwrap();
    let wad2 = File::open(path2).unwrap();
    let wad3 = File::open(path3).unwrap();
    let wad4 = File::open(path4).unwrap();

    let wad1 = unsafe { MmapOptions::new().map(&wad1) }.unwrap();
    let wad2 = unsafe { MmapOptions::new().map(&wad2) }.unwrap();
    let wad3 = unsafe { MmapOptions::new().map(&wad3) }.unwrap();
    let wad4 = unsafe { MmapOptions::new().map(&wad4) }.unwrap();

    let mut builder = SegmentTableBuilder::new();
    builder.add_wad(path1_sub.as_bytes(), &wad1, &wad2).unwrap();
    builder.add_wad(path3_sub.as_bytes(), &wad3, &wad4).unwrap();

    let seg_table = builder.flatten();
    println!("length is {}", seg_table.len());

    let mut loader = PatchLoader::wait_can_patch(lol_path.as_bytes()).await.unwrap();
    loader.freeze_process().unwrap();

    loader.load_and_resume(&elf_file, b"C:/Users/josh/Desktop/storage", &seg_table).unwrap();

    println!("done loading!");
}

