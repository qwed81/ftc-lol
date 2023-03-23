use serde::{Deserialize, Serialize};

pub mod client;
pub mod server;
pub mod entry_cache;
pub mod stream_util;

#[derive(Serialize, Deserialize, Clone, Debug, Hash, PartialEq, Eq)]
pub struct ModEntry {
    pub hash: String,
    pub name: String,
    pub file_size: u64,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub enum ModEntryState {
    Active,
    InActive,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExtendedModEntry {
    pub entry: ModEntry,
    pub state: ModEntryState,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
enum ConnectionHeader {
    Subscribe,
    Download,
    Upload
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ServerStateUpdateMessage {
    server_mods: Vec<ExtendedModEntry>
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ServerStateUpdateRequest {
    entry: ModEntry,
    requested_state: ModEntryState
}


