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
    target_dir.pop();

    build_windows(&target_dir);
}

fn build_windows(target: &Path) {
    let pd = "src/patch";
    let bootstrap_o = join(target, "bootstrap.o");
    let cmd = format!("nasm -f elf32 -o {bootstrap_o} bootstrap.s");
    execute(pd, cmd).unwrap();

    let patch_o = join(target, "patch.o");
    let cmd = format!("clang -c -fno-stack-protector -nostdlib -fPIC -target i386-unknown-linux-elf -Wall -o {patch_o} patch.c");
    execute(pd, cmd).unwrap();

    // link the items together
    let cmd = format!("clang -fuse-ld=lld -fPIE -nostdlib -target i386-unknown-linux-elf -o patch bootstrap.o patch.o");
    execute(target.to_str().unwrap(), cmd).unwrap();
}
