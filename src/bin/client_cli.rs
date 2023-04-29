use memmap2::MmapOptions;
use sha2::{Digest, Sha256};
use skins::patch_loader::PatchLoader;
use skins::pkg::client::PkgClient;
use skins::pkg::{PkgCache, PkgDir};

use chrono::Local;
use std::collections::VecDeque;
use std::env;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::{Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

fn import(dir: &PkgDir, cache: &mut PkgCache, path: &Path) -> Result<String, ()> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => {
            println!("could not open requested file");
            return Err(());
        }
    };

    let mem = match unsafe { MmapOptions::new().map(&file) } {
        Ok(mem) => mem,
        Err(_) => {
            println!("could not open memory map file");
            return Err(());
        }
    };

    let mut hasher = Sha256::new();
    hasher.update(&mem);
    let hash_string = format!("{:x}", hasher.finalize());

    let new_path = dir.get_pkg_path(&hash_string).unwrap();
    let mut copy_to = match File::create(&new_path) {
        Ok(copy_to) => copy_to,
        Err(_) => {
            println!("could not create new file");
            return Err(());
        }
    };

    if let Err(_) = io::copy(&mut file, &mut copy_to) {
        println!("could not copy to new file");
        return Err(());
    }

    cache.add(hash_string.clone());
    Ok(hash_string)
}

fn print_help() {
    println!("status - returns message from the server to test connection");
    println!("import [path] - copies and hashes a seg file to local package list");
    println!("upload [hash] - uploades a package to the remote package list");
    println!("download [hash] - downloads a package from the server manually");
    println!("set [hash] [active | inactive] - sets a package active/inactive");
    println!("local - lists local packages");
    println!("remote - lists remote packages");
    println!("active - outputs hash of current active package");
    println!("clear - clears the terminal");
    println!("vl - views loader logs without consuming them");
    println!("cl - views loader logs and removes them");
    println!("exit - exists without risk of package corruption");
    println!("\nnote: download of active package will occur automatically on game load");
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

fn upload(client: &PkgClient, cache: &PkgCache, hash: &str) -> Result<(), ()> {
    let hash = match get_prefixed_hash(&hash, cache.hashes()) {
        PrefixedHash::Valid(hash) => hash,
        PrefixedHash::TooMany => {
            println!("more than one hash matches the prefix");
            return Err(());
        }
        PrefixedHash::NotAny => {
            println!("no hashes match the prefix");
            return Err(());
        }
    };
    client.upload(String::from(hash))
}

fn download(client: &PkgClient, cache: &mut PkgCache, hash: &str) -> Result<(), ()> {
    let hashes = match client.list() {
        Ok(hashes) => hashes,
        Err(_) => return Err(()),
    };

    let hash = match get_prefixed_hash(&hash, hashes.iter()) {
        PrefixedHash::Valid(hash) => hash,
        PrefixedHash::TooMany => {
            println!("more than one hash matches the prefix");
            return Err(());
        }
        PrefixedHash::NotAny => {
            println!("no hashes match the prefix");
            return Err(());
        }
    };
    client.download(cache, String::from(hash))
}

fn remove(dir: &PkgDir, cache: &mut PkgCache, hash: &str) -> Result<(), ()> {
    let hash = match get_prefixed_hash(&hash, cache.hashes()) {
        PrefixedHash::Valid(hash) => hash,
        PrefixedHash::TooMany => {
            println!("more than one hash matches the prefix");
            return Err(());
        }
        PrefixedHash::NotAny => {
            println!("no hashes match the prefix");
            return Err(());
        }
    };

    cache.remove(&hash);
    let path = dir.get_pkg_path(&hash).unwrap();
    match fs::remove_file(&path) {
        Ok(_) => Ok(()),
        Err(_) => Err(()),
    }
}

fn set(client: &PkgClient, hash: &str, active_text: &str) -> Result<(), ()> {
    let hashes = match client.list() {
        Ok(hashes) => hashes,
        Err(_) => return Err(()),
    };

    let hash = match get_prefixed_hash(&hash, hashes.iter()) {
        PrefixedHash::Valid(hash) => hash,
        PrefixedHash::TooMany => {
            println!("more than one hash matches the prefix");
            return Err(());
        }
        PrefixedHash::NotAny => {
            println!("no hashes match the prefix");
            return Err(());
        }
    };

    match active_text {
        "active" => client.activate(&hash),
        "inactive" => client.deactivate(&hash),
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

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("The ip must be supplied as the first argument, and port as the second");
        return;
    }

    let ip = args[1].clone();
    let port = args[2].parse().unwrap();

    let dir = Arc::new(PkgDir::new(PathBuf::from("client_packages")));

    // if we put a RW lock on cache, then it ends actually helping us as then downloads will wait
    // on downloads and uploads, but multiple uploads can happen at once
    let cache = Arc::new(RwLock::new(PkgCache::from_dir_sync(&dir).unwrap()));

    let client = Arc::new(PkgClient::new(dir.as_ref().clone(), ip, port));
    let buffer = Arc::new(Mutex::new(VecDeque::new()));

    // this task is responsible for outputting to the
    // console from the buffer and taking in input
    let client2 = Arc::clone(&client);
    let dir2 = Arc::clone(&dir);
    let cache2 = Arc::clone(&cache);
    let buffer2 = Arc::clone(&buffer);
    thread::spawn(move || take_commands(client2, dir2, cache2, buffer2));

    // just does a loop trying to load the patch, and pushes
    // to the back of the buffer, so it will be printed when
    // asked by the command
    load_patch_loop(client, dir, cache, buffer);
}

fn get_root_path() -> PathBuf {
    let mut path = env::current_exe().unwrap();
    path.pop();
    path
}

fn print_status(client: &PkgClient) {
    let start = Instant::now();
    let status_result = client.get_status();
    let time_taken = (Instant::now() - start).as_millis();

    match status_result {
        Ok(status) => println!("status: {}, delay: {}ms", status, time_taken),
        Err(_) => println!("the server could not be reached"),
    }
}

fn take_commands(
    client: Arc<PkgClient>,
    dir: Arc<PkgDir>,
    cache: Arc<RwLock<PkgCache>>,
    buffer: Arc<Mutex<VecDeque<String>>>,
) {
    let stdin = io::stdin();
    let mut str_buf = String::new();
    println!("client cli, type help for commands");
    print_status(&client);

    loop {
        print!("> ");
        io::stdout().lock().flush().unwrap();

        str_buf.clear();
        stdin.read_line(&mut str_buf).unwrap();
        let cmd: Vec<&str> = str_buf.trim().split_whitespace().collect();
        if cmd.len() < 1 {
            continue;
        }

        match cmd[0] {
            "help" => print_help(),
            "status" => print_status(&client),
            "import" => {
                if cmd.len() < 2 {
                    println!("import requires a path");
                    continue;
                }

                let mut cache = cache.write().unwrap();
                if let Err(_) = import(&dir, &mut cache, &PathBuf::from(cmd[1])) {
                    println!("import failed");
                }
            }
            "upload" => {
                if cmd.len() < 2 {
                    println!("upload requires a hash");
                    continue;
                }

                let cache = cache.read().unwrap();
                if let Err(_) = upload(&client, &cache, &cmd[1]) {
                    println!("upload failed");
                }
            }
            "download" => {
                if cmd.len() < 2 {
                    println!("download requires a hash");
                    continue;
                }

                let mut cache = cache.write().unwrap();
                if let Err(_) = download(&client, &mut cache, &cmd[1]) {
                    println!("download failed");
                }
            }
            "set" => {
                if cmd.len() < 3 {
                    println!("setting requires the hash and the active");
                    continue;
                }

                if let Err(_) = set(&client, cmd[1], cmd[2]) {
                    println!("could not set package state");
                }
            }
            "local" => {
                let cache = cache.read().unwrap();
                print_hash_list(cache.hashes())
            }
            "remote" => {
                let hashes = match client.list() {
                    Ok(hashes) => hashes,
                    Err(_) => {
                        println!("could not get remote package list");
                        continue;
                    }
                };
                print_hash_list(hashes.iter());
            }
            "active" => {
                let active = match client.get_active() {
                    Ok(active) => active,
                    Err(_) => {
                        println!("could not get active package");
                        continue;
                    }
                };

                match active {
                    Some(active) => println!("{}", active),
                    None => println!("there is no package active"),
                }
            }
            "rm" => {
                if cmd.len() < 2 {
                    println!("removing a file requires the package hash");
                    continue;
                }

                let mut cache = cache.write().unwrap();
                if let Err(_) = remove(&dir, &mut cache, &cmd[1]) {
                    println!("there was an error removing the package");
                }
            }
            "exit" => {
                // make sure that everything is done loading before exiting
                // so we don't end up in a state without a proper download
                let _ = cache.write();

                std::process::exit(0);
            }
            "cl" => {
                let mut buffer = buffer.lock().unwrap();
                while buffer.is_empty() == false {
                    let message = buffer.pop_front().unwrap();
                    println!("{}", message);
                }
            }
            "vl" => {
                for message in buffer.lock().unwrap().iter() {
                    println!("{}", message);
                }
            }
            "clear" => {
                print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
                println!("client cli, type help for commands");
            }
            _ => println!("Invalid command"),
        }
    }
}

const LOL_PATH: &[u8] = b"C:\\Riot Games\\League of Legends\\Game\\League of Legends.exe";

fn add_message(buffer: &Arc<Mutex<VecDeque<String>>>, message: String) {
    let time = Local::now();
    let message = format!("[{}] {}", time.format("%H:%M:%S"), message);
    buffer.lock().unwrap().push_back(message);
}

fn load_patch_loop(
    client: Arc<PkgClient>,
    dir: Arc<PkgDir>,
    cache: Arc<RwLock<PkgCache>>,
    buffer: Arc<Mutex<VecDeque<String>>>,
) {
    let root = get_root_path();
    let elf_file = File::open(root.join("patch")).unwrap();
    let elf_file = unsafe { MmapOptions::new().map(&elf_file) }.unwrap();

    // if path starts with \?\\ then remove it
    let root_u8 = root.as_os_str().to_str().unwrap().as_bytes();
    let mut root_u8_ref = root_u8;
    if &root_u8[0..1] == &[b'\\'] {
        root_u8_ref = &root_u8[4..];
    }

    loop {
        add_message(
            &buffer,
            format!(
                "waiting for process: {}",
                std::str::from_utf8(LOL_PATH).unwrap()
            ),
        );
        let mut loader = match PatchLoader::wait_can_patch(LOL_PATH) {
            Ok(loader) => loader,
            Err(e) => {
                let m1 = String::from("loader could not wait for process");
                let m2 = format!("{}, code: {:?}", e.message, e.code);
                add_message(&buffer, m1);
                add_message(&buffer, m2);
                break;
            }
        };

        add_message(&buffer, String::from("process found"));

        // once the process loads, then freeze it before doing
        // any work to prevent race condition
        if let Err(e) = loader.freeze_process() {
            let m1 = String::from("loader could not freeze process");
            let m2 = format!("{}, code: {:?}", e.message, e.code);
            add_message(&buffer, m1);
            add_message(&buffer, m2);
            break;
        }

        add_message(&buffer, String::from("started loading"));

        let active: Option<String> = match client.get_active() {
            Ok(active) => active,
            Err(_) => {
                add_message(
                    &buffer,
                    String::from("could not get active package, loading game without patch"),
                );
                loader
                    .resume_without_load()
                    .expect("could not resume, manually close LOL");
                loader.wait_process_closed().unwrap();

                add_message(&buffer, String::from("waiting for exit"));
                continue;
            }
        };

        let active = match active {
            Some(active) => active,
            None => {
                loader
                    .resume_without_load()
                    .expect("could not resume, manually close LOL");

                loader.wait_process_closed().unwrap();
                add_message(&buffer, String::from("waiting for exit"));
                continue;
            }
        };

        {
            let mut cache = cache.write().unwrap();
            if cache.contains(&active) == false {
                let m1 = format!("do not have {}", &active);
                let m2 = format!("downloading {}", &active);
                add_message(&buffer, m1);
                add_message(&buffer, m2);

                if let Err(_) = client.download(&mut cache, active.clone()) {
                    add_message(
                        &buffer,
                        String::from("package download failed, loading game without patch"),
                    );
                    loader
                        .resume_without_load()
                        .expect("could not resume, manually close LOL");

                    loader.wait_process_closed().unwrap();
                    add_message(&buffer, String::from("waiting for exit"));
                    continue;
                }
            }
        }

        let seg_table_path = dir.get_pkg_path(&active).unwrap();
        let mut retry_count = 0;
        let seg_table_file = loop {
            match File::open(&seg_table_path) {
                Ok(file) => break file,
                Err(_) => {
                    // it is possible the file can not be opened the first time because
                    // the downloader will still have the lock on it. Keep trying to
                    // get the lock
                    if retry_count < 5 {
                        let message =
                            format!("could not open package file (attempt {}", retry_count);
                        buffer.lock().unwrap().push_back(message);

                        retry_count += 1;
                        thread::sleep(Duration::from_secs(1));
                        continue;
                    }

                    add_message(
                        &buffer,
                        String::from("could not open package file, loading game without patch"),
                    );
                    loader
                        .resume_without_load()
                        .expect("could not resume, manually close LOL");
                    loader.wait_process_closed().unwrap();
                }
            };
        };

        let seg_table = unsafe { MmapOptions::new().map(&seg_table_file) }.unwrap();
        if let Err(_) = loader.load_and_resume(&elf_file, root_u8_ref, &seg_table) {
            add_message(
                &buffer,
                String::from("loader could not load properly, starting game anyways"),
            );
            loader
                .resume_without_load()
                .expect("could not resume, manually close LOL");
        }

        add_message(&buffer, String::from("loaded sucessfully"));
        add_message(&buffer, String::from("waiting for exit"));
        loader.wait_process_closed().unwrap();
    }
}
