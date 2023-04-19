use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::collections::HashSet;
use tokio::io;
use tokio::fs;

pub mod client;
pub mod server;

#[derive(Clone)]
pub struct PkgDir {
    root: PathBuf
}

#[derive(Deserialize, Serialize)]
pub struct ActivePkg {
    hash: Option<String>
}

impl PkgDir {

    pub fn new(root: PathBuf) -> PkgDir {
        PkgDir {
            root
        }
    }

    pub fn get_pkg_path(&self, hash: &str) -> Option<PathBuf> {
        let mut path = self.root.clone();
        path.push(hash);

        // prevent getting path from outside of directory
        if path.parent()? != &self.root {
            return None;
        }
        Some(path)
    }
}

pub struct PkgCache {
    hashes: HashSet<String>
}

impl PkgCache {

    pub async fn from_dir(dir: &PkgDir) -> io::Result<PkgCache> {
        let mut dir = fs::read_dir(&dir.root).await?;
        let mut hashes = HashSet::new();
        while let Some(pkg_entry) = dir.next_entry().await? {
            hashes.insert(String::from(pkg_entry.file_name().to_str().unwrap()));
        }

        Ok(PkgCache { hashes })
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.hashes.contains(hash)
    }

    pub fn add(&mut self, hash: String) {
        self.hashes.insert(hash);
    }

    pub fn hashes(&self) -> impl Iterator<Item=&str> {
        self.hashes.iter().map(|x| x.as_str())
    }
}
