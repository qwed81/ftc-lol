use std::path::PathBuf;
use skins::pkg::{PkgDir, PkgCache, server};
use std::env;

#[tokio::main]
async fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 2 {
        println!("The port must be supplied as the first argument");
        return;
    }

    let port = args[1].parse().unwrap();
    let dir = PkgDir::new(PathBuf::from("server_packages"));
    let cache = PkgCache::from_dir(&dir).await.unwrap();

    println!("listening on port: {}", port);
    server::listen(dir, cache, port).await;
}
