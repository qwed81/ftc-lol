use skins::segment_table::SegmentTableBuilder;
use memmap2::MmapOptions;
use std::fs::File;

fn main() {
    let mut table = SegmentTableBuilder::new();
    // let path1 = "C:/Users/josh/Dekstop/Aatrox.wad.client";
    let path1 = "C:/Users/josh/Desktop/cslol-manager/profiles/Default Profile/DATA/FINAL/Champions/Nunu.wad.client";
    let path2 = "C:/Riot Games/League of Legends/Game/DATA/FINAL/Champions/Nunu.wad.client";

    let wad1 = File::open(path1).unwrap();
    let wad2 = File::open(path2).unwrap();

    let wad1 = unsafe { MmapOptions::new().map(&wad1) }.unwrap();
    let wad2 = unsafe { MmapOptions::new().map(&wad2) }.unwrap();

    table.add_wad(path1.as_bytes(), &wad1, &wad2).unwrap();
    table.print_stats();
}