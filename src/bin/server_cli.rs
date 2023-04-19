use std::path::PathBuf;
use skins::pkg::{PkgDir, PkgCache, server};

#[tokio::main]
async fn main() {
    let dir = PkgDir::new(PathBuf::from("_test/server"));
    let cache = PkgCache::from_dir(&dir).await.unwrap();
    server::listen(dir, cache).await;
}
