use skins::patch_loader::PatchLoader;
use skins::pkg::client::PkgClient;
use skins::pkg::{PkgCache, PkgDir};
use std::path::PathBuf;
use std::fs::File;
use memmap2::MmapOptions;
use std::env;
use std::time::Duration;
use tokio::time;

const LOL_PATH: &[u8] = b"C:\\Riot Games\\League of Legends\\Game\\League of Legends.exe";

fn get_root_path() -> PathBuf {
    let mut path = env::current_exe().unwrap();
    path.pop();
    path
}

#[tokio::main]
async fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("the ip must be supplied as the first argument, and port as the second");
        return;
    }

    let ip = args[1].clone();
    let port = args[2].parse().unwrap();

    let path = PathBuf::from("client_packages");
    let dir = PkgDir::new(path);
    let mut cache = PkgCache::from_dir(&dir).await.unwrap();
    let client = PkgClient::new(dir.clone(), ip, port);

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
        println!("waiting for process: {}", std::str::from_utf8(LOL_PATH).unwrap());
        let mut loader = match PatchLoader::wait_can_patch(LOL_PATH).await {
            Ok(loader) => loader,
            Err(e) => {
                println!("loader could not wait for process");
                println!("{}\nerror: {:?}", e.message, e.code);
                break;
            }
        };

        // once the process loads, then freeze it before doing
        // any work to prevent race condition
        if let Err(e) = loader.freeze_process() {
            println!("loader could not freeze process");
            println!("{}\nerror: {:?}", e.message, e.code);
            break;
        }

        let active: Option<String> = match client.get_active().await {
            Ok(active) => active,
            Err(_) => {
                println!("could not get active package, loading game without patch");
                loader.resume_without_load().expect("could not resume, manually close LOL");
                loader.wait_process_closed().await.unwrap();
                println!("waiting for exit");
                continue;
            }
        };

        let active = match active {
            Some(active) => active,
            None => {
                loader.resume_without_load().expect("could not resume, manually close LOL");
                loader.wait_process_closed().await.unwrap();
                println!("waiting for exit");
                continue
            }
        };

        if cache.contains(&active) == false {
            println!("do not have {}", &active);
            println!("downloading {}", &active);

            if let Err(_) = client.download(&mut cache, active.clone()).await {
                println!("package download failed, loading game without patch");
                loader.resume_without_load().expect("could not resume, manually close LOL");
                loader.wait_process_closed().await.unwrap();
                println!("waiting for exit");
                continue;
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
                        println!("could not open package file (attempt {}), retrying in 1 second", retry_count);
                        retry_count += 1;

                        time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }

                    println!("could not open package file, loading game without patch");
                    loader.resume_without_load().expect("could not resume, manually close LOL");
                    loader.wait_process_closed().await.unwrap();
                }
            };
        };

        let seg_table = unsafe { MmapOptions::new().map(&seg_table_file) }.unwrap();
        if let Err(_) = loader.load_and_resume(&elf_file, root_u8_ref, &seg_table) {
            println!("loader could not load properly, starting game anyways");
            loader.resume_without_load().expect("could not resume, manually close LOL");
        }

        println!("loaded sucessfully");
        println!("waiting for exit");
        loader.wait_process_closed().await.unwrap();
    }
}
