use skins::repository::client::{self, RequestSender, StateUpdate, UpdateReceiver};
use skins::repository::entry_cache::{self, EntryCache};
use skins::repository::{stream_util, ExtendedModEntry, ModEntry, ModEntryState};
use std::sync::{Arc, Mutex};
use std::io::Write;
use tokio::fs::File;
use tokio::io::{self, AsyncBufReadExt, AsyncSeekExt, BufReader, SeekFrom};

struct ServerRepositoryState {
    entries: Vec<ExtendedModEntry>,
    connected: bool,
}

#[tokio::main]
async fn main() {
    let ip = "127.0.0.1:5001";
    let (mut request_sender, update_receiver) = client::connect(ip)
        .await
        .expect("could not connect to server");

    let server_state = Arc::new(Mutex::new(ServerRepositoryState {
        entries: Vec::new(),
        connected: true,
    }));

    let mut cache = EntryCache::from_dir("_test_client").await.unwrap();
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
            "upload" => upload(&input),
            "set" => set(&input, &mut request_sender, &server_state).await,
            "remote" => list_remote(&input, &server_state),
            "local" => list_local(&input, &cache),
            "import" => import(&input, &mut cache).await,
            _ => {
                println!("invalid command");
            }
        }

        buf.clear();
    }
}

enum MatchPrefix {
    NoMatches,
    MultipleMatches(usize),
    Match(ModEntry),
}

fn match_hash_prefix<'a>(
    prefix: &str,
    iter: impl Iterator<Item = &'a ExtendedModEntry> + 'a,
) -> MatchPrefix {
    let mut total_matches = 0;
    let mut last_matched = None;
    for entry in iter {
        if prefix == &entry.entry.hash[0..prefix.len()] {
            total_matches += 1;
            last_matched = Some(entry);
        }
    }

    match total_matches {
        0 => MatchPrefix::NoMatches,
        1 => {
            let matched = &last_matched.unwrap().entry;
            MatchPrefix::Match(ModEntry {
                hash: matched.hash.to_owned(),
                name: matched.name.to_owned(),
                file_size: matched.file_size,
            })
        }
        count => MatchPrefix::MultipleMatches(count),
    }
}

async fn handle_updates(
    state: Arc<Mutex<ServerRepositoryState>>,
    mut update_receiver: UpdateReceiver<StateUpdate>,
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
    println!("Name: {}", &entry.hash);
    println!("Hash: {}", &entry.name);
    println!("File size: {}", &entry.file_size);
    if let Some(state) = state {
        let state_str = match state {
            ModEntryState::Active => "active",
            ModEntryState::InActive => "inactive",
        };
        println!("State: {}", state_str);
    }
}

async fn import(args: &Vec<&str>, cache: &mut EntryCache) {
    if args.len() != 3 {
        println!("Import requires 3 arguments");
        return;
    }

    let name = String::from(args[1]);
    let path = args[2];
    let mut file = match File::open(path).await {
        Ok(file) => file,
        Err(_) => {
            println!("Could not open file");
            return;
        }
    };

    let file_len = file.metadata().await.unwrap().len();
    let hash = stream_util::hash_full_stream(&mut file).await.unwrap();
    file.seek(SeekFrom::Start(0)).await.unwrap();

    let new_path = cache.create_entry_path(&hash);
    let mut new_file = match File::create(&new_path).await {
        Ok(file) => file,
        Err(_) => {
            println!("Could not create new file");
            return;
        }
    };

    stream_util::copy_stream_and_verify_hash(&mut file, &mut new_file, file_len, &hash)
        .await
        .unwrap();

    let meta_path = cache.create_meta_path(&hash);
    let entry = ModEntry {
        hash,
        name,
        file_size: file_len,
    };
    entry_cache::write_metadata(&meta_path, &entry)
        .await
        .unwrap();
    entry_cache::verify_can_add_entry(&meta_path, &new_path)
        .await
        .unwrap();
    cache.add_entry(entry);
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

fn download(args: &Vec<&str>) {}

fn upload(args: &Vec<&str>) {}

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
