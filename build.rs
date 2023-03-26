use std::env;
use std::process::{ExitStatus, Command};
use std::path::Path;
use std::path::PathBuf;
use std::io;

fn execute(wd: &str, cmd_str: String) -> io::Result<ExitStatus> {
    let args: Vec<&str> = cmd_str.split_whitespace().collect();
    Command::new(args[0]).current_dir(wd).args(&args[1..]).status()
}

fn join(dir: &Path, name: &str) -> String {
    let bootstrap_o = dir.join(name);
    bootstrap_o.to_str().unwrap().to_owned()
}

fn main() {
    // get the /target/*/ directory to put the output files in
    let mut target_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    target_dir.pop();
    target_dir.pop();

    println!("cargo:rerun-if-changed=src/patch");
    if cfg!(target_os="windows") {
        build_windows(&target_dir);
    }
}

fn build_windows(target: &Path) {
    let pd = "src/patch";
    let cmd = format!("nasm -o {} -f elf32 bootstrap.s", join(target, "bootstrap.o"));
    execute(pd, cmd).unwrap();

    let cmd = format!("nasm -o {} -f elf32 as.s", join(target, "as.o"));
    execute(pd, cmd).unwrap();

    let args = "-c -nostdlib -target i386-unknown-linux-elf -Wall";
    let cmd = format!("clang {} -o {} patch.c", args, join(target, "patch.o"));
    execute(pd, cmd).unwrap();

    let args = "-fuse-ld=lld -static-pie -nostdlib -target i386-unknown-linux-elf";
    let objs = format!("{} {} {}", join(target, "bootstrap.o"), join(target, "as.o"), join(target, "patch.o"));
    let cmd = format!("clang {} {} {}", args, join(target, "patch"), &objs);
    execute(pd, cmd).unwrap();
}
