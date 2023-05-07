import os
import shutil
import subprocess

# build the actual program
subprocess.run(["cargo", "build", "--release"])

# copy delete folder if it exists to start new
if os.path.exists("./target/release-client"):
    shutil.rmtree("./target/release-client")
os.mkdir("./target/release-client")

if os.path.exists("./target/release-server"):
    shutil.rmtree("./target/release-server")
os.mkdir("./target/release-server")

# copy files over
for file in ["patch", "client_cli.exe"]:
    shutil.copyfile("./target/release/" + file, "./target/release-client/" + file)

for file in ["server_cli.exe"]:
    shutil.copyfile("./target/release/" + file, "./target/release-server/" + file)

# make the required directories
os.mkdir("./target/release-client/client_packages")
os.mkdir("./target/release-client/mods")

os.mkdir("./target/release-server/server_packages")

# copy the environment variable file over to release (don't store secrets in this env var)
shutil.copyfile("./client.env", "./target/release-client/client.env")
print("client.env CONNECT_TO ip needs to be changed to remote server")

shutil.copyfile("./server.env", "./target/release-server/server.env")

# write out the easy click bat file that starts the process
with open("./target/release-client/ftc.bat", "w") as f:
    f.write("start client_cli")

with open("./target/release-server/ftc_server.bat", "w") as f:
    f.write("start server_cli")

