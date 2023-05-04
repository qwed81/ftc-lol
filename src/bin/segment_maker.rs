use ftc::segment_table;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

fn print_help() {
    println!("usage: [output name] [mod dir] [mod1] [mod2]...");
}

fn main() {
    dotenvy::from_path("client.env").expect("client.env required");

    if env::args().count() < 3 {
        print_help();
        return;
    }

    let mut args = env::args().peekable();
    _ = args.next();

    let output_name = match args.next() {
        Some(name) => name,
        None => {
            print_help();
            return;
        }
    };

    let mod_dir = match args.next() {
        Some(name) => name,
        None => {
            print_help();
            return;
        }
    };

    // create string in the format of --mods:[mod1]/[mod2]
    let mut mods_str = String::from("--mods:");
    while let Some(mut mod_name) = args.next() {
        if args.peek().is_some() {
            mod_name.push('/');
        }
        mods_str.extend(mod_name.chars())
    }

    let overlay_path = PathBuf::from("_temp_files");
    fs::create_dir(&overlay_path).expect("could not create temp directory");

    let game_path = ftc::lol_game_folder_path();
    let game_path = game_path.to_str().expect("invalid path");

    let mut child = Command::new("./mod-tools.exe")
        .arg("mkoverlay")
        .arg(&mod_dir)
        .arg(overlay_path.to_str().unwrap())
        .arg(&format!("--game:{}", game_path))
        .arg(&mods_str)
        .arg("--noTFT")
        .arg("--ignoreConflict")
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.wait().unwrap();

    let table = segment_table::from_raw_path(&overlay_path).unwrap();
    fs::write(output_name, &table).unwrap();
    fs::remove_dir_all(&overlay_path).unwrap();
}
