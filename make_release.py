import os
import shutil
import subprocess
import sys

if os.path.exists("./target/release-min"):
    shutil.rmtree("./target/release-min")

if os.path.exists("./target/release-full"):
    shutil.rmtree("./target/release-full")

os.mkdir("./target/release-min")
os.mkdir("./target/release-full")

subprocess.run(["cargo", "build", "--release"])

for file in ["patch", "segment_maker.exe", "server_cli.exe", "client_cli.exe"]:
    shutil.copyfile("./target/release/" + file, "./target/release-full/" + file)

for file in ["patch", "client_cli.exe"]:
    shutil.copyfile("./target/release/" + file, "./target/release-min/" + file)

# plan to remove in the future when proper support is implemented
if len(sys.argv) < 2:
    print("path to mod-tools is required")
    exit(1)

lol_tools_path = sys.argv[1]
name = os.path.basename(os.path.realpath(lol_tools_path))
if name != "mod-tools.exe":
    print(f"file {name} is not mod-tools")
    exit(1)

shutil.copy(lol_tools_path, "./target/release-full/mod-tools.exe")

os.mkdir("./target/release-min/client_packages")

os.mkdir("./target/release-full/client_packages")
os.mkdir("./target/release-full/server_packages")

