use skins::segment_table;
use std::fs;
use std::path::PathBuf;

pub fn main() {
    let path = "C:\\Users\\josh\\Desktop\\cslol-manager\\installed\\bowser Jr and bowser\\WAD\\Nunu.wad.client";
    let path = PathBuf::from(path);
    let table = segment_table::from_fantome_file(&path).unwrap();
    fs::write("output.seg", &table).unwrap();

    /* 
    let old_wad = "C:/Users/josh/Desktop/cslol-manager/profiles/Default Profile/DATA/FINAL/Champions/Nunu.wad.client";
    let old_file = File::open(old_wad).unwrap();
    let old_wad = unsafe { MmapOptions::new().map(&old_file) }.unwrap();
    wad::print_entries(&wad);
    println!("--------");
    wad::print_entries(&old_wad);
    */

}