use skins::repository::client::{self, RequestSender, UpdateReceiver};
use skins::repository::mod_fs::{self, EntryCache, ModDir};
use skins::repository::{ExtendedModEntry, ModEntry, ModEntryState};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio::io::{self, AsyncBufReadExt, BufReader};
use std::env;

struct ServerRepositoryState {
    entries: Vec<ExtendedModEntry>,
    connected: bool,
}

const IP: &'static str = "127.0.0.1:5001";

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let dir = if args.len() > 1 {
        &args[1]
    } else {
        "_test/client"
    };

    let ip = IP;
    let (mut request_sender, update_receiver) = client::connect(ip)
        .await
        .expect("could not connect to server");

    let server_state = Arc::new(Mutex::new(ServerRepositoryState {
        entries: Vec::new(),
        connected: true,
    }));

    let dir = ModDir::new(dir);
    let mut cache = EntryCache::load_from_dir(&dir).await.unwrap();

    tokio::spawn(handle_updates(Arc::clone(&server_state), update_receiver));
    let mut stdin = BufReader::new(io::stdin());

    let mut buf = String::new();
    println!("client cli, type help");
    while server_state.lock().unwrap().connected {
        print!("> ");
        std::io::stdout().flush().unwrap();
        stdin.read_line(&mut buf).await.unwrap();
        let input: Vec<&str> = buf.split_whitespace().collect();
        if input.len() == 0 {
            continue;
        }

        match input[0] {
            "exit" => return,
            "help" => print_help(),
            "download" => download(&input, &dir, &mut cache, &server_state).await,
            "upload" => upload(&input, &dir, &cache, &server_state).await,
            "set" => set(&input, &mut request_sender, &server_state).await,
            "remote" => list_remote(&input, &server_state),
            "local" => list_local(&input, &cache),
            "import" => import(&input, &dir, &mut cache).await,
            _ => {
                println!("invalid command");
            }
        };

        buf.clear();
    }
}
async fn handle_updates(
    state: Arc<Mutex<ServerRepositoryState>>,
    mut update_receiver: UpdateReceiver,
) {
    loop {
        let update = update_receiver.next().await;
        match update {
            Some(mods) => state.lock().unwrap().entries = mods,
            None => {
                println!("Disconnected");
                state.lock().unwrap().connected = false;
                break;
            }
        }
    }
}

fn print_entry(entry: &ModEntry, state: Option<ModEntryState>) {
    println!("  Name: {}", &entry.name);
    println!("  Hash: {}", &entry.hash);
    println!("  File len: {} bytes", &entry.file_len);
    if let Some(state) = state {
        let state_str = match state {
            ModEntryState::Active => "Active",
            ModEntryState::InActive => "Inactive",
        };
        println!("  State: {}", state_str);
    }

    println!();
}

async fn import(args: &Vec<&str>, dir: &ModDir, cache: &mut EntryCache) {
    if args.len() != 3 {
        println!("Import requires 3 arguments");
        return;
    }

    let name = String::from(args[1]);
    let path = Path::new(args[2]);
    let lock = match mod_fs::import_external_entry(dir, path, name).await {
        Ok(lock) => lock,
        Err(e) => {
            println!("Could not import mod, error: {:?}", e);
            return;
        }
    };
    cache.add_entry(lock);
}

fn list_remote(_args: &Vec<&str>, server_state: &Arc<Mutex<ServerRepositoryState>>) {
    println!("Remote mods are: ");
    let mut has_one = false;
    for extended_entry in &server_state.lock().unwrap().entries {
        print_entry(&extended_entry.entry, Some(extended_entry.state));
        has_one = true;
    }

    if has_one == false {
        println!();
    }
}

fn list_local(_args: &Vec<&str>, cache: &EntryCache) {
    println!("Local mods are: ");
    let mut has_one = false;
    for entry in cache.entries() {
        print_entry(entry, None);
        has_one = true;
    }

    if has_one == false {
        println!();
    }
}

enum MatchPrefix {
    NoMatches,
    MultipleMatches(usize),
    Match(ModEntry),
}

fn match_hash_prefix(prefix: &str, iter: &Vec<impl AsRef<ModEntry>>) -> MatchPrefix {
    let mut total_matches = 0;
    let mut last_matched = None;
    for entry in iter {
        if prefix == &entry.as_ref().hash[0..prefix.len()] {
            total_matches += 1;
            last_matched = Some(entry);
        }
    }

    match total_matches {
        0 => MatchPrefix::NoMatches,
        1 => {
            let matched = last_matched.as_ref().unwrap().as_ref();
            MatchPrefix::Match(ModEntry {
                hash: matched.hash.to_owned(),
                name: matched.name.to_owned(),
                file_len: matched.file_len,
            })
        }
        count => MatchPrefix::MultipleMatches(count),
    }
}

fn get_intersection_from_prefix_list(
    hash_prefixes: &[&str],
    entries: &Vec<impl AsRef<ModEntry>>,
) -> Option<Vec<ModEntry>> {
    let mut output = Vec::new();
    for &prefix in hash_prefixes {
        match match_hash_prefix(prefix, &entries) {
            MatchPrefix::NoMatches => {
                println!("Hash {} does not prefix any local mods", prefix);
                return None;
            }
            MatchPrefix::MultipleMatches(amt) => {
                println!("Hash {} matches multiple ({}) local mods, lengthen the input to select the correct file", prefix, amt);
                return None;
            }
            MatchPrefix::Match(entry) => output.push(entry),
        }
    }
    Some(output)
}

async fn download(
    args: &Vec<&str>,
    dir: &ModDir,
    cache: &mut EntryCache,
    server_state: &Arc<Mutex<ServerRepositoryState>>,
) {
    let entries = server_state.lock().unwrap().entries.clone();
    let hash_prefixes = &args[1..];
    let mut downloads = match get_intersection_from_prefix_list(hash_prefixes, &entries) {
        Some(downloads) => downloads,
        None => return,
    };

    // if we already have the mod, then there is no point in trying to download it
    for entry in cache.entries() {
        for i in (0..downloads.len()).rev() {
            if &downloads[i].hash == &entry.hash {
                let e = &downloads[i];
                println!("Already have mod: {} ({})", &e.name, &e.hash);
                downloads.swap_remove(i);
            }
        }
    }
    if downloads.len() == 0 {
        return;
    }

    let mut download = match client::download(IP, dir, downloads).await {
        Ok(download) => download,
        Err(e) => {
            println!("Could not start download, error: {}", e);
            return;
        }
    };

    while let Some(entry) = download.peek_next() {
        println!("Downloading: {} ({})", &entry.name, &entry.hash);
        let lock = match download.download_next().await {
            Ok(lock) => {
                println!("Download completed");
                lock
            }
            Err(e) => {
                println!("Download failed with error: {:?}", e);
                break;
            }
        };

        cache.add_entry(lock);
    }
}

async fn upload(
    args: &Vec<&str>,
    dir: &ModDir,
    cache: &EntryCache,
    server_state: &Arc<Mutex<ServerRepositoryState>>,
) {
    let entries = cache.entries().collect();
    let hash_prefixes = &args[1..];
    let mut uploads = match get_intersection_from_prefix_list(hash_prefixes, &entries) {
        Some(entries) => entries,
        None => return,
    };

    // don't try to upload if it is already on the server
    for entry in &server_state.lock().unwrap().entries {
        for i in (0..uploads.len()).rev() {
            if &uploads[i].hash == &entry.entry.hash {
                let e = &uploads[i];
                println!("Server already has mod: {} ({})", &e.name, &e.hash);
                uploads.swap_remove(i);
            }
        }
    }
    if uploads.len() == 0 {
        return;
    }

    let mut upload = match client::upload(IP, dir, uploads).await {
        Ok(updater) => updater,
        Err(e) => {
            println!("Could not start upload, error: {}", e);
            return;
        }
    };

    while let Some(entry) = upload.peek_next() {
        println!("Uploading: {} ({})", &entry.name, &entry.hash);
        match upload.upload_next().await {
            Ok(_) => println!("Upload completed"),
            Err(e) => {
                println!("Upload failed with error: {:?}", e);
                break;
            }
        }
    }
}

async fn set(
    args: &Vec<&str>,
    request_sender: &mut RequestSender,
    server_state: &Arc<Mutex<ServerRepositoryState>>,
) {
    if args.len() != 3 {
        println!("expected 3 arguments");
    }

    let hash_prefix = args[1];
    let mod_state = match args[2] {
        "active" => ModEntryState::Active,
        "inactive" => ModEntryState::InActive,
        _ => {
            println!("invalid mod state option");
            return;
        }
    };

    let match_prefix = match_hash_prefix(hash_prefix, &server_state.lock().unwrap().entries);
    let entry = match match_prefix {
        MatchPrefix::NoMatches => {
            println!("No mod exists with that hash");
            return;
        }
        MatchPrefix::MultipleMatches(_) => {
            println!("Multiple mods exist with that prefix");
            return;
        }
        MatchPrefix::Match(entry) => entry,
    };

    match request_sender.request_set_mod_state(entry, mod_state).await {
        Ok(_) => (),
        Err(e) => {
            println!("Could not send request, error: {:?}", e);
            return;
        }
    }
}

fn print_help() {
    println!("Commands: ");
    println!("  exit");
    println!("  remote");
    println!("  local");
    println!("  import [mod name] [file path]");
    println!("  set [mod hash] [active | inactive]");
    println!("  download [mod hash...]");
    println!("  upload [mod hash...]");
}
