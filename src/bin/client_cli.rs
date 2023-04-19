use memmap2::MmapOptions;
use sha2::{Digest, Sha256};
use skins::pkg::client::PkgClient;
use skins::pkg::{PkgCache, PkgDir};
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

fn import(dir: &PkgDir, cache: &mut PkgCache, path: &Path) -> Result<String, ()> {
    let mut file = File::open(path).unwrap();
    let mem = unsafe { MmapOptions::new().map(&file) }.unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&mem);
    let hash_string = format!("{:x}", hasher.finalize());

    let new_path = dir.get_pkg_path(&hash_string).unwrap();
    let mut copy_to = File::create(&new_path).unwrap();
    io::copy(&mut file, &mut copy_to).unwrap();

    cache.add(hash_string.clone());
    Ok(hash_string)
}

fn print_help() {
    println!("import [path]");
    println!("upload [hash]");
    println!("download [hash]");
    println!("set [hash] [active | inactive]");
    println!("local");
    println!("remote");
    println!("active");
}

enum PrefixedHash {
    Valid(String),
    TooMany,
    NotAny,
}

fn get_prefixed_hash<I, A>(hash: &str, iter: I) -> PrefixedHash
where
    I: Iterator<Item = A>,
    A: AsRef<str>,
{
    let mut count = 0;
    let mut selected = None;
    for h in iter {
        let h = h.as_ref();
        if h.starts_with(hash) {
            selected = Some(String::from(h));
            count += 1;
        }
        if count > 1 {
            return PrefixedHash::TooMany;
        }
    }

    match selected {
        Some(selected) => PrefixedHash::Valid(selected),
        None => PrefixedHash::NotAny,
    }
}

async fn upload(client: &PkgClient, cache: &PkgCache, hash: &str) -> Result<(), ()> {
    let hash = match get_prefixed_hash(&hash, cache.hashes()) {
        PrefixedHash::Valid(hash) => hash,
        PrefixedHash::TooMany => {
            println!("More than one hash matches the prefix");
            return Err(());
        }
        PrefixedHash::NotAny => {
            println!("No hashes match the prefix");
            return Err(());
        }
    };
    client.upload(String::from(hash)).await
}

async fn download(client: &PkgClient, cache: &mut PkgCache, hash: &str) -> Result<(), ()> {
    let hashes = match client.list().await {
        Ok(hashes) => hashes,
        Err(_) => return Err(()),
    };

    let hash = match get_prefixed_hash(&hash, hashes.iter()) {
        PrefixedHash::Valid(hash) => hash,
        PrefixedHash::TooMany => {
            println!("More than one hash matches the prefix");
            return Err(());
        }
        PrefixedHash::NotAny => {
            println!("No hashes match the prefix");
            return Err(());
        }
    };
    client.download(cache, String::from(hash)).await
}

async fn set(client: &PkgClient, hash: &str, active_text: &str) -> Result<(), ()> {
    let hashes = match client.list().await {
        Ok(hashes) => hashes,
        Err(_) => return Err(()),
    };

    let hash = match get_prefixed_hash(&hash, hashes.iter()) {
        PrefixedHash::Valid(hash) => hash,
        PrefixedHash::TooMany => {
            println!("More than one hash matches the prefix");
            return Err(());
        }
        PrefixedHash::NotAny => {
            println!("No hashes match the prefix");
            return Err(());
        }
    };

    match active_text {
        "active" => client.activate(&hash).await,
        "inactive" => client.deactivate(&hash).await,
        _ => {
            println!("Only active and inactive are allowed as options");
            return Err(());
        }
    }
}

fn print_hash_list<I, A>(hashes: I)
where
    I: Iterator<Item = A>,
    A: AsRef<str>,
{
    for hash in hashes {
        let hash = hash.as_ref();
        println!("{}", hash);
    }
}

#[tokio::main]
async fn main() {
    let dir = PkgDir::new(PathBuf::from("./_test/client1"));
    let mut cache = PkgCache::from_dir(&dir).await.unwrap();
    let client = PkgClient::new(dir.clone(), String::from("127.0.0.1"), 8000);

    let stdin = io::stdin();
    let mut buffer = String::new();
    println!("client cli, type help for commands");

    loop {
        print!("> ");
        io::stdout().lock().flush().unwrap();

        buffer.clear();
        stdin.read_line(&mut buffer).unwrap();
        let cmd: Vec<&str> = buffer.trim().split_whitespace().collect();
        if cmd.len() < 1 {
            continue;
        }

        match cmd[0] {
            "help" => print_help(),
            "import" => {
                if cmd.len() < 2 {
                    println!("Import requires a path");
                    continue;
                }

                if let Err(_) = import(&dir, &mut cache, &PathBuf::from(cmd[1])) {
                    println!("Import failed");
                }
            }
            "upload" => {
                if cmd.len() < 2 {
                    println!("Upload requires a hash");
                    continue;
                }
                if let Err(_) = upload(&client, &cache, &cmd[1]).await {
                    println!("Upload failed");
                }
            }
            "download" => {
                if cmd.len() < 2 {
                    println!("Download requires a hash");
                    continue;
                }
                if let Err(_) = download(&client, &mut cache, &cmd[1]).await {
                    println!("Download failed");
                }
            },
            "set" => {
                if cmd.len() < 3 {
                    println!("Setting requires the hash and the active");
                    continue;
                }

                if let Err(_) = set(&client, cmd[1], cmd[2]).await {
                    println!("Could not set package state");
                }
            }
            "local" => print_hash_list(cache.hashes()),
            "remote" => {
                let hashes = match client.list().await {
                    Ok(hashes) => hashes,
                    Err(_) => {
                        println!("Could not get remote package list");
                        continue;
                    }
                };
                print_hash_list(hashes.iter());
            },
            "active" => {
                let active = match client.get_active().await {
                    Ok(active) => active,
                    Err(_) => {
                        println!("Could not get active package");
                        continue;
                    }
                };

                match active { Some(active) => println!("{}", active),
                    None => println!("There is no package active")
                }
            }
            _ => println!("Invalid command"),
        }

    }
}
