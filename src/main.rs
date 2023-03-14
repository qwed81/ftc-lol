use std::path::Path;
use std::time::Duration;

use skins::patch_loader::{Loader, load};

enum Input {
    Pid, Name, Constant
}

fn main() {
    
    let input = Input::Constant;

    let lol_path = "C:\\Riot Games\\League of Legends\\Game\\League of Legends.exe";
    // let lol_path = "C:\\Program Files (x86)\\Notepad++\\notepad++.exe";

    let loader = match input {
        Input::Pid => input_pid(),
        Input::Name => input_name(),
        Input::Constant => Loader::wait_spawn(lol_path.as_bytes(), Duration::from_secs(10_000)).unwrap()
    };

    let file_path = Path::new("patch");
    // std::thread::sleep(Duration::from_millis(3000));
    load::load_patch(file_path, loader).unwrap();
    println!("done loading!");
}

fn input_name() -> Loader {
    println!("input file name");
    let mut name = String::new();
    std::io::stdin().read_line(&mut name).unwrap();
    let name = name.trim().as_bytes();
    Loader::wait_spawn(name, Duration::from_secs(60_000)).unwrap()
}

fn input_pid() -> Loader {
    println!("input pid: ");
    let mut pid = String::new();
    std::io::stdin().read_line(&mut pid).unwrap();
    let pid = pid.trim().parse::<u32>().unwrap();
    Loader::from_pid(pid).unwrap()
}
