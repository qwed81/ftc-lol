use skins::repository::mod_fs::{ModDir, EntryCache};
use skins::repository::server;

#[tokio::main]
async fn main() {
    println!("initializing cache");
    let dir = ModDir::new("_test/server");
    let cache = EntryCache::load_from_dir(&dir).await.unwrap();

    println!("waiting for connections");
    server::listen_for_connections(cache, dir).await.unwrap();
}
