use super::entry_cache::EntryCache;
use super::stream_util;
use super::{
    ConnectionHeader, ExtendedModEntry, ModEntry, ModEntryState, ServerStateUpdateMessage,
    ServerStateUpdateRequest
};
use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};
use std::time::Duration;
use tokio::io;
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpListener, TcpStream,
};
use tokio::time;

struct SharedEntries {
    cache: Arc<RwLock<EntryCache>>,
    state_map: Arc<RwLock<HashMap<String, ModEntryState>>>,
    state_map_version: Arc<AtomicU64>,
}

impl Clone for SharedEntries {
    fn clone(&self) -> SharedEntries {
        SharedEntries {
            cache: Arc::clone(&self.cache),
            state_map: Arc::clone(&self.state_map),
            state_map_version: Arc::clone(&self.state_map_version),
        }
    }
}

pub async fn listen_for_connections(cache: EntryCache) -> io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:5001").await?;

    // maps the hash to their ModEntryState
    let shared_entries = SharedEntries {
        cache: Arc::new(RwLock::new(cache)),
        state_map: Arc::new(RwLock::new(HashMap::new())),
        state_map_version: Arc::new(AtomicU64::new(0)),
    };

    loop {
        let (stream, _ip) = listener.accept().await?;
        tokio::spawn(handle_connection(stream, shared_entries.clone()));
    }
}

async fn handle_connection(mut stream: TcpStream, entries: SharedEntries) {
    let header: ConnectionHeader = match stream_util::read_message(&mut stream).await {
        Ok(header) => header,
        Err(_) => return,
    };

    match header {
        ConnectionHeader::Subscribe => {
            let (reader, writer) = stream.into_split();
            tokio::spawn(handle_requests(reader, entries.clone()));
            handle_send_updates(writer, entries).await;
        }
        ConnectionHeader::Download => handle_download().await,
        ConnectionHeader::Upload => handle_upload().await,
    }
}

async fn handle_requests(mut reader: OwnedReadHalf, shared_entries: SharedEntries) {
    loop {
        let message: ServerStateUpdateRequest = match stream_util::read_message(&mut reader).await {
            Ok(message) => message,
            Err(_) => break
        };

        let mut state_map = shared_entries.state_map.write().unwrap();
        match state_map.get_mut(&message.entry.hash) {
            Some(state_ref) => *state_ref = message.requested_state,
            None => continue
        }
    }
}

fn map_entries<'a>(
    iter: impl Iterator<Item = &'a ModEntry> + 'a,
    state_map: &HashMap<String, ModEntryState>,
) -> Vec<ExtendedModEntry> {
    iter.map(|entry| ExtendedModEntry {
        entry: ModEntry {
            hash: entry.hash.clone(),
            name: entry.name.clone(),
            file_size: entry.file_size,
        },
        state: *state_map.get(&entry.hash).unwrap(),
    })
    .collect()
}

async fn handle_send_updates(mut writer: OwnedWriteHalf, shared_entries: SharedEntries) {
    // we use these to track if there were any changes since the last time we checked
    let mut last_entries = shared_entries.cache.read().unwrap().get_current_iteration();
    let mut last_state = shared_entries.state_map_version.load(Ordering::Acquire);

    loop {
        let current_entries = shared_entries.cache.read().unwrap().get_current_iteration();
        let current_state = shared_entries.state_map_version.load(Ordering::Acquire);

        // there was a change since the last time we checked
        if current_entries != last_entries || current_state != last_state {
            let extended_entries = {
                let cache = shared_entries.cache.read().unwrap();
                let state_map = shared_entries.state_map.read().unwrap();
                map_entries(cache.entries(), &state_map)
            };

            let message = ServerStateUpdateMessage {
                server_mods: extended_entries,
            };
            match stream_util::write_message(&mut writer, &message).await {
                Ok(_) => (),
                Err(_) => break,
            };

            last_entries = current_entries;
            last_state = current_state;
        }

        time::sleep(Duration::from_millis(10)).await;
    }
}

async fn handle_upload() {}

async fn handle_download() {}
