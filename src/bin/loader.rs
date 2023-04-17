use skins::repository::client::{self, UpdateReceiver};
use skins::repository::mod_fs::{self, ModDir, EntryCache};
use skins::repository::{ModEntry, ExtendedModEntry, ModEntryState};
use skins::patch_loader::PatchLoader;
use std::sync::{Arc, Mutex};
use std::net::SocketAddrV4;
use std::path::PathBuf;
use std::fs::File;
use std::env;
use memmap2::MmapOptions;

fn print_help() {
    println!("usage: [server_ip:port] [dir]");
}

async fn listen_for_updates(state: Arc<Mutex<Vec<ExtendedModEntry>>>, mut updater: UpdateReceiver) {
    println!("connected");

    while let Some(new_state) = updater.next().await {
        *state.lock().unwrap() = new_state;
    }

    println!("disconnected");
}

fn get_active_mod(state: &Vec<ExtendedModEntry>) -> Option<ModEntry> {
    for entry in state {
        if let ModEntryState::Active = entry.state {
            return Some(entry.entry.clone())
        }
    }
    None
}

const LOL_PATH: &[u8] = "C:\\Riot Games\\League of Legends\\Game\\League of Legends.exe".as_bytes();

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        print_help();
        return;
    }

    let addr: SocketAddrV4 = args[1].parse().unwrap();
    let path = PathBuf::from(&args[2]);
    let dir = ModDir::new(path);
    let mut cache = EntryCache::load_from_dir(&dir).await.unwrap();

    let state = Arc::new(Mutex::new(Vec::new()));

    let (_req, res) = client::connect(&addr).await.unwrap();
    tokio::spawn(listen_for_updates(state.clone(), res));

    let mut loader = PatchLoader::wait_can_patch(LOL_PATH).await.unwrap();
    loader.freeze_process().unwrap();

    // once it is loaded, figure out what is active
    let active = match get_active_mod(&state.lock().unwrap()) {
        Some(active) => active,
        None => {
            println!("no mods were active");
            return;
        }
    };

    // if the mod is not downloaded, then install it
    let active_hash = active.hash.clone();
    if cache.contains(&active_hash) == false {
        let mut downloader = client::download(&addr, &dir, vec![active]).await.unwrap();
        let lock = downloader.download_next().await.unwrap();
        cache.add_entry(lock);
    }

    // gets the path which this executable is running in
    let mut cwd = env::current_exe().unwrap();
    cwd.pop();

    let mut patch_path = cwd.clone();
    patch_path.push("patch");

    let seg_table = File::open(dir.create_entry_path(&active_hash)).unwrap();
    let seg_table = unsafe { MmapOptions::new().map(&seg_table) }.unwrap();

    let patch = File::open(patch_path).unwrap();
    let patch = unsafe { MmapOptions::new().map(&patch) }.unwrap();


    let cwd_bytes = cwd.as_os_str().to_str().unwrap().as_bytes();
    loader.load_and_resume(&patch, &cwd_bytes, &seg_table).unwrap();
}

