use std::env;
use std::process::Command;
use std::path::Path;
use std::path::PathBuf;

fn execute(wd: &str, cmd_str: String) {
    let args: Vec<&str> = cmd_str.split_whitespace().collect();
    let mut command = Command::new(args[0]);
    command.current_dir(wd).args(&args[1..]);
    let output = command.output().unwrap().stderr;
    let output = String::from_utf8_lossy(&output);
    let lines = output.split('\n');
    for line in lines {
        if line.len() > 0 {
            println!("cargo:warning={}", line);
        }
    }
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
    execute(pd, cmd);

    let patch_o = join(target, "patch.o");
    let cmd = format!("clang -c -fno-stack-protector -nostdlib -fPIC -target i386-unknown-linux-elf -Wall -o {patch_o} patch.c");
    execute(pd, cmd);

    // link the items together
    let cmd = format!("clang -fuse-ld=lld -fPIE -nostdlib -target i386-unknown-linux-elf -o patch bootstrap.o patch.o");
    execute(target.to_str().unwrap(), cmd);
}
