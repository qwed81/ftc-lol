use skins::repository::entry_cache::EntryCache;
use skins::repository::server;

#[tokio::main]
async fn main() {
    println!("initializing cache");
    let cache = EntryCache::from_dir("_test/server").await.unwrap();
    println!("waiting for connections");
    server::listen_for_connections(cache).await.unwrap();
}
