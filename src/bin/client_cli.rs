use ftc::cli;
use ftc::patch_loader::PatchLoader;
use ftc::pkg::client::PkgClient;
use ftc::pkg::{PkgCache, PkgDir};
use memmap2::MmapOptions;

use chrono::Local;
use std::collections::VecDeque;
use std::env;
use std::fs::File;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::{Mutex, RwLock};
use std::thread;
use std::time::Duration;

fn print_help() {
    println!("status - returns message from the server to test connection");
    println!("import [name] [path] - copies and hashes a seg file to local package list");
    println!("merge [new name] [mod1] [mod2]... - makes a new package from fantome files");
    println!("upload [hash] - uploades a package to the remote package list");
    println!("download [hash] - downloads a package from the server manually");
    println!("set [hash] [active | inactive] - sets a package active/inactive");
    println!("local - lists local packages");
    println!("remote - lists remote packages");
    println!("active - outputs hash of current active package");
    println!("clear - clears the terminal");
    println!("vlog - views loader logs");
    println!("clog - clears logs");
    println!("exit - exists without risk of package corruption");
    println!("\nnote: download of active package will occur automatically on game load");
}

fn main() {
    dotenvy::from_path("client.env").expect("client.env required");

    let connect_to = env::var("CONNECT_TO").expect("CONNECT_TO environment varible required");
    let addr: SocketAddr = connect_to
        .parse()
        .expect("CONNECT_TO not valid socket addr");
    let pkg_path = env::var("PKG_PATH").expect("PKG_PATH environment variable required");

    let dir = PkgDir::new(PathBuf::from(pkg_path));
    let client = PkgClient::new(dir.clone(), &addr);
    let cache = PkgCache::from_dir_blocking(dir.clone()).unwrap();

    let dir_ref = Arc::new(dir);
    let client_ref = Arc::new(client);

    // if we put a RW lock on cache, then it ends actually helping us as then downloads will wait
    // on downloads and uploads, but multiple uploads can happen at once
    let cache_ref = Arc::new(RwLock::new(cache));

    // buffer strings that will be used as the logs
    let buffer = Arc::new(Mutex::new(VecDeque::new()));

    // this task is responsible for outputting to the
    // console from the buffer and taking in input
    let client_ref2 = Arc::clone(&client_ref);
    let dir_ref2 = Arc::clone(&dir_ref);
    let cache_ref2 = Arc::clone(&cache_ref);
    let buffer_ref2 = Arc::clone(&buffer);
    thread::spawn(move || take_commands(client_ref2, dir_ref2, cache_ref2, buffer_ref2));

    // just does a loop trying to load the patch, and pushes
    // to the back of the buffer, so it will be printed when
    // asked by the command
    load_patch_loop(client_ref, dir_ref, cache_ref, buffer);
}

fn get_root_path() -> PathBuf {
    let mut path = env::current_exe().unwrap();
    path.pop();
    path
}

fn take_commands(
    client: Arc<PkgClient>,
    dir: Arc<PkgDir>,
    cache: Arc<RwLock<PkgCache>>,
    buffer: Arc<Mutex<VecDeque<String>>>,
) {
    let stdin = io::stdin();
    let mut str_buf = String::new();
    println!(
        "ftc client cli, lol patch {}, type help for commands",
        ftc::get_current_patch()
    );
    cli::print_status(&client);

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
            "status" => cli::print_status(&client),
            "import" => {
                if cmd.len() < 2 {
                    println!("import requires a path and name");
                    continue;
                }

                if cmd.len() < 3 {
                    println!("import requires a name");
                    continue;
                }

                let mut cache = cache.write().unwrap();
                cli::import(
                    &dir,
                    &mut cache,
                    String::from(cmd[1]),
                    &PathBuf::from(&cmd[2]),
                );
            }
            "merge" => {
                if cmd.len() < 2 {
                    println!("merge requires a name");
                    continue;
                }

                if cmd.len() < 3 {
                    println!("merge requires at least one mod");
                    continue;
                }

                let paths: Vec<&str> = Vec::from(&cmd[2..]);
                let mut cache = cache.write().unwrap();
                cli::merge(&dir, &mut cache, String::from(cmd[1]), paths);
            }
            "upload" => {
                if cmd.len() < 2 {
                    println!("upload requires a hash");
                    continue;
                }

                let cache = cache.read().unwrap();
                cli::upload(&client, &cache, &cmd[1]);
            }
            "download" => {
                if cmd.len() < 2 {
                    println!("download requires a hash");
                    continue;
                }

                let mut cache = cache.write().unwrap();
                cli::download(&client, &mut cache, &cmd[1]);
            }
            "set" => {
                if cmd.len() < 3 {
                    println!("setting requires the hash and the active");
                    continue;
                }

                cli::set(&client, cmd[1], cmd[2]);
            }
            "local" => {
                let cache = cache.read().unwrap();
                cli::print_meta_list(cache.iter());
            }
            "remote" => {
                let Ok(hashes) = client.list() else {
                    println!("could not get remote package list");
                    continue;
                };
                cli::print_meta_list(hashes.iter());
            }
            "active" => {
                let Ok(active) = client.get_active() else {
                    println!("could not get active package");
                    continue;
                };

                match active {
                    Some(active) => println!("{}", cli::fmt_pkg(&active)),
                    None => println!("there is no package active"),
                }
            }
            "rm" => {
                if cmd.len() < 2 {
                    println!("removing a file requires the package hash");
                    continue;
                }

                let mut cache = cache.write().unwrap();
                cli::remove(&dir, &mut cache, &cmd[1]);
            }
            "exit" => {
                // make sure that everything is done loading before exiting
                // so we don't end up in a state without a proper download
                // once everything is done then we can write it out to a file
                // before exiting
                let ok = match cache.write().unwrap().flush_blocking() {
                    Ok(_) => 0,
                    Err(_) => {
                        println!("could not write package metadata");
                        -1
                    }
                };
                std::process::exit(ok);
            }
            "clog" => {
                let mut buffer = buffer.lock().unwrap();
                buffer.clear()
            }
            "vlog" => {
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
            format!("waiting for process: {:?}", ftc::lol_exe_path()),
        );

        // wait until the patcher can patch before doing anything
        let mut loader = match PatchLoader::wait_can_patch(&ftc::lol_exe_path()) {
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

        // once the process loads, freeze it before doing
        // any work to prevent race condition
        if let Err(e) = loader.freeze_process() {
            let m1 = String::from("loader could not freeze process");
            let m2 = format!("{}, code: {:?}", e.message, e.code);
            add_message(&buffer, m1);
            add_message(&buffer, m2);
            break;
        }

        add_message(&buffer, String::from("started loading"));

        // get the currently active package from the server
        let Ok(active) = client.get_active() else {
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
        };

        // check if there is an active package
        let Some(active) = active else {
            loader
                .resume_without_load()
                .expect("could not resume, manually close LOL");

            loader.wait_process_closed().unwrap();
            add_message(&buffer, String::from("waiting for exit"));
            continue;
        };

        // download the package if it does not exist locally
        {
            let mut cache = cache.write().unwrap();
            if cache.contains_hash(&active.hash) == false {
                let m1 = format!("do not have {}", cli::fmt_pkg(&active));
                let m2 = format!("downloading {}", cli::fmt_pkg(&active));
                add_message(&buffer, m1);
                add_message(&buffer, m2);

                if let Err(_) = client.download(&mut cache, active.hash.clone()) {
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

        let seg_table_path = dir.get_pkg_path(&active.hash).unwrap();
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
        if let Err(e) = loader.load_and_resume(&elf_file, root_u8_ref, &seg_table) {
            add_message(
                &buffer,
                String::from("loader could not load properly, starting game anyways"),
            );

            let m = format!("{}, code: {:?}", e.message, e.code);
            add_message(&buffer, m);

            loader
                .resume_without_load()
                .expect("could not resume, manually close LOL");
        }

        add_message(&buffer, String::from("loaded sucessfully"));
        add_message(&buffer, String::from("waiting for exit"));
        loader.wait_process_closed().unwrap();
    }
}
