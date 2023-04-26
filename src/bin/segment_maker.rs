use skins::segment_table;
use std::fs;
use std::path::PathBuf;
use std::env;

fn print_help() {
    println!("usage: [root_dir] [optional: output_name]");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_help();
        return;
    }

    let output_name = match args.get(2) {
        Some(output_name) => output_name,
        None => "out.seg"
    };

    let mod_dir = PathBuf::from(&args[1]);
    let table = segment_table::from_combined_dir(&mod_dir).unwrap();

    fs::write(output_name, &table).unwrap();
}
