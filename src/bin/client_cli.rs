use skins::repository::client::{self, RequestSender, StateUpdate, UpdateReceiver};
use skins::repository::mod_fs::{self, EntryCache, ModDir};
use skins::repository::{ExtendedModEntry, ModEntry, ModEntryState};
use std::path::Path;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tokio::io::{self, AsyncBufReadExt, BufReader};

struct ServerRepositoryState {
    entries: Vec<ExtendedModEntry>,
    connected: bool,
}

const IP: &'static str = "127.0.0.1:5001";

#[tokio::main]
async fn main() {
    let ip = IP;
    let (mut request_sender, update_receiver) = client::connect(ip)
        .await
        .expect("could not connect to server");

    let server_state = Arc::new(Mutex::new(ServerRepositoryState {
        entries: Vec::new(),
        connected: true,
    }));

    let dir = ModDir::new("_test/client");
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
            "download" => download(&input),
            "upload" => upload(&input, &dir, &cache).await,
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

enum MatchPrefix {
    NoMatches,
    MultipleMatches(usize),
    Match(ModEntry),
}

fn match_hash_prefix(
    prefix: &str,
    iter: impl Iterator<Item = impl AsRef<ModEntry>>,
) -> MatchPrefix {
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

async fn handle_updates(
    state: Arc<Mutex<ServerRepositoryState>>,
    mut update_receiver: UpdateReceiver,
) {
    loop {
        let update = update_receiver.next().await;
        match update {
            StateUpdate::Connected => (),
            StateUpdate::StateUpdate(mods) => state.lock().unwrap().entries = mods,
            StateUpdate::Disconnected => {
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
            ModEntryState::Active => "active",
            ModEntryState::InActive => "inactive",
        };
        println!("State: {}", state_str);
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
    for extended_entry in &server_state.lock().unwrap().entries {
        print_entry(&extended_entry.entry, Some(extended_entry.state));
    }
}

fn list_local(_args: &Vec<&str>, cache: &EntryCache) {
    println!("Local mods are: ");
    for entry in cache.entries() {
        print_entry(entry, None);
    }
}

fn get_entries_from_hash_list(hashes: &[&str], cache: &EntryCache) -> Option<Vec<ModEntry>> {
    let mut entries = Vec::new();
    for &prefix in hashes {
        match match_hash_prefix(prefix, cache.entries()) {
            MatchPrefix::NoMatches => {
                println!("Hash {} does not prefix any local mods", prefix);
                return None;
            }
            MatchPrefix::MultipleMatches(amt) => {
                println!("Hash {} matches multiple ({}) local mods", prefix, amt);
                return None;
            }
            MatchPrefix::Match(entry) => entries.push(entry),
        }
    }
    Some(entries)
}

fn download(args: &Vec<&str>) {}

async fn upload(args: &Vec<&str>, dir: &ModDir, cache: &EntryCache) {
    let entries = match get_entries_from_hash_list(&args[1..], &cache) {
        Some(entries) => entries,
        None => return,
    };

    let mut upload = match client::upload(IP, dir, entries).await {
        Ok(updater) => updater,
        Err(e) => {
            println!("Could not start upload, error: {}", e);
            return;
        }
    };

    while let Some(entry) = upload.peek_next() {
        println!("Uploading {} ({})", &entry.name, &entry.hash);
        match upload.upload_next().await {
            Ok(_) => println!("Upload completed"),
            Err(e) => println!("Upload failed with error: {:?}", e)
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

    let match_prefix = match_hash_prefix(hash_prefix, server_state.lock().unwrap().entries.iter());
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
        Ok(_) => println!("request sent"),
        Err(_) => {
            println!("could not send request");
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
