use ftc::pkg::{server, PkgCache, PkgDir};
use std::env;
use std::path::PathBuf;

const PORT: u16 = 9313;

#[tokio::main]
async fn main() {
    dotenvy::from_path("server.env").expect("server.env required");

    let pkg_path = env::var("PKG_PATH").expect("PKG_PATH environment variable required");
    let dir = PkgDir::new(PathBuf::from(pkg_path));
    let cache = PkgCache::from_dir(&dir).await.unwrap();

    println!("listening on port: {}", PORT);
    server::listen(dir, cache, PORT).await;
}
