use std::path::Path;

use skins::patch_loader::{Loader, load};

fn main() {
    println!("input pid: ");
    let mut pid = String::new();
    std::io::stdin().read_line(&mut pid).unwrap();
    let pid = pid.trim().parse::<u32>().unwrap();

    let loader = Loader::from_pid(pid).unwrap();

    let file_path = Path::new("patch");
    load::load_patch(file_path, loader).unwrap();

    println!("done loading!");
}
