use std::env;
use std::fs::File;
use std::path::PathBuf;

use ftc::patch_loader::PatchLoader;
use memmap2::MmapOptions;

fn get_root_path() -> PathBuf {
    let mut path = env::current_exe().unwrap();
    path.pop();
    path
}

#[tokio::main]
async fn main() {
    let root = get_root_path();
    let elf_file = File::open(root.join("patch")).unwrap();
    let elf_file = unsafe { MmapOptions::new().map(&elf_file) }.unwrap();

    let seg_file = File::open(root.join("mod.seg")).unwrap();
    let seg_table = unsafe { MmapOptions::new().map(&seg_file) }.unwrap();

    let root_u8 = root.as_os_str().to_str().unwrap().as_bytes();

    // if path starts with \?\\ then remove it
    let mut root_u8_ref = root_u8;
    if &root_u8[0..1] == &[b'\\'] {
        root_u8_ref = &root_u8[4..];
    }

    println!("path is: {}", std::str::from_utf8(root_u8_ref).unwrap());
    let mut loader = PatchLoader::wait_can_patch(&ftc::lol_game_folder_path()).unwrap();
    loader.freeze_process().unwrap();

    loader
        .load_and_resume(&elf_file, root_u8_ref, &seg_table)
        .unwrap();

    println!("done loading!");
}
