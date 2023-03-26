use std::env;
use std::process::{ExitStatus, Command};
use std::path::Path;
use std::path::PathBuf;
use std::io;

fn main() {
    // get the /target/*/ directory to put the output files in
    let mut target_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    target_dir.pop();
    target_dir.pop();

    println!("cargo:rerun-if-changed=src/patch");
    if cfg!(target_os="linux") {
        build_windows(&target_dir);
    }
}

fn cmd(wd: &str, cmd_str: &str) -> Result<ExitStatus> {
    let args: Vec<&str> = cmd_str.split_whitespace().collect();
    Command::new(args[0]).args(&args[1..])
}

fn path(target_dir: &Path, name: &str) -> String {
    let bootstrap_o = target_dir.join("bootstrap.o");
    bootstrap_o.to_str().unwrap().to_owned()
}

fn build_windows(target_dir: &Path) {
    let wd = "src/patch";
    let boostrap_args = ["-o", &path(target_dir, "bootstrap_o"), "-f", "elf32", "bootstrap.s"];

    let as_o = target_dir.join("as.o");
    let as_o = as_o.to_str().unwrap();
    let as_args = ["-o", as_o, "-f", "elf32", "as.s"];

    let patch_o = 
}
