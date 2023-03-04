import os
import subprocess
import sys

def build(release: bool):
    build_rs = "cargo build"
    if release:
        build_rs = "cargo build --release"

    result = subprocess.run(build_rs)
    if result.returncode != 0:
        exit(1)
    print("rust built successfully")

    if release:
        print("release mode not setup")
        exit(1)

    result = subprocess.run("make")

    if result.returncode != 0:
        exit(1)
    print("c built successfully")


def run():
    build(False)
    os.chdir("target/debug")
    subprocess.run("code.exe")

for arg in sys.argv:
    if arg == 'build' or arg == 'b':
        build(False)
    elif arg == 'run' or arg == 'r':
        run()
    elif arg == 'make' or arg == 'm':
        build(True)

