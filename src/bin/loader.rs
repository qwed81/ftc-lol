use skins::patch_loader::PatchLoader;
use skins::pkg::client::PkgClient;
use skins::pkg::{PkgCache, PkgDir};
use std::path::PathBuf;
use std::fs::File;
use memmap2::MmapOptions;
use std::env;

const LOL_PATH: &[u8] = b"C:/Riot Games/League of Legends/Game/League of Legends.exe\0";

fn get_root_path() -> PathBuf {
    let mut path = env::current_exe().unwrap();
    path.pop();
    path
}

#[tokio::main]
async fn main() {
    let path = PathBuf::from("packages");
    let dir = PkgDir::new(path);
    let mut cache = PkgCache::from_dir(&dir).await.unwrap();
    let client = PkgClient::new(dir.clone(), String::from("127.0.0.1"), 8000);

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
        let mut loader = PatchLoader::wait_can_patch(LOL_PATH)
            .await
            .expect("Loader can not wait for process");
        // once the process loads, then freeze it before doing
        // any work to prevent race condition
        loader
            .freeze_process()
            .expect("Loader could not freeze process");

        let active: Option<String> = match client.get_active().await {
            Ok(active) => active,
            Err(_) => {
                println!("Could not get active package, loading game without patch");
                loader.resume_without_load();
                continue;
            }
        };

        let active = match active {
            Some(active) => active,
            None => continue
        };

        if cache.contains(&active) == false {
            if let Err(_) = client.download(&mut cache, active.clone()).await {
                println!("Package download failed, loading game without patch");
                loader.resume_without_load();
                continue;
            }
        }

        let seg_table_path = dir.get_pkg_path(&active).unwrap();
        let seg_table_file = match File::open(&seg_table_path) {
            Ok(file) => file,
            Err(_) => {
                println!("Could not open package file, loading game without patch");
                loader.resume_without_load();
                continue;
            }
        };

        let seg_table = unsafe { MmapOptions::new().map(&seg_table_file) }.unwrap();
        if let Err(_) = loader.load_and_resume(&elf_file, root_u8_ref, &seg_table) {
            println!("Loader could not load properly, starting game anyways");
            loader.resume_without_load();
        }
    }
}
