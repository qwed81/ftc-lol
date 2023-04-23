use skins::segment_table::SegmentTableBuilder;
use skins::wad;
use std::fs::{self, File};
use std::path::PathBuf;
use memmap2::MmapOptions;

pub fn main() {
    let game_path = PathBuf::from("C:/Riot Games/League of Legends/Game/DATA/FINAL");
    let mut builder = SegmentTableBuilder::index().unwrap();
    let new_wad = "C:\\Users\\josh\\Desktop\\cslol-manager\\installed\\bowser Jr and bowser\\WAD\\Nunu.wad.client";
    let file = File::open(new_wad).unwrap();
    let wad = unsafe { MmapOptions::new().map(&file) }.unwrap();

    let header = wad::read_header(&wad).unwrap();
    for i in 0..header.entry_count as usize {
        let entry = wad::read_entry(&wad, i).unwrap();
        builder.replace_entry(&wad, entry);
    }

    let result = builder.flatten();
    fs::write("output.seg", &result).unwrap();

    println!("len: {}", result.len());
}