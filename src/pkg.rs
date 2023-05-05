use axum::http::HeaderName;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

pub mod client;
pub mod server;

const NAME_HEADER: HeaderName = HeaderName::from_static("x-pkg-name");
const PATCH_HEADER: HeaderName = HeaderName::from_static("x-pkg-patch");

#[derive(Deserialize, Serialize)]
pub struct ActivePkg {
    hash: Option<String>,
}
#[derive(Clone)]
pub struct PkgDir {
    root: PathBuf,
}

#[derive(Deserialize, Serialize)]
pub enum ConnectionStatus {
    Connected,
}

impl PkgDir {
    pub fn new(root: PathBuf) -> PkgDir {
        PkgDir { root }
    }

    fn get_meta_path(&self) -> PathBuf {
        let mut path = self.root.clone();
        path.push("meta.json");
        path
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

#[derive(Deserialize, Serialize)]
pub struct PkgMeta {
    hash: String,
    name: String,
    patch: String,
}

pub struct PkgCache {
    data: Vec<PkgMeta>,
}

impl PkgCache {
    pub fn from_dir_sync(dir: &PkgDir) -> io::Result<PkgCache> {
        let data = std::fs::read(&dir.get_meta_path())?;
        let data: Vec<PkgMeta> = serde_json::from_slice(&data).expect("data is corrupted");

        /*
        let dir = std::fs::read_dir(&dir.root)?;
        let mut hashes = HashSet::new();
        for file in dir {
            let pkg_entry = file?;
            hashes.insert(String::from(pkg_entry.file_name().to_str().unwrap()));
        }
        */

        Ok(PkgCache { data })
    }

    pub fn remove(&mut self, hash: &str) {
        for i in 0..self.data.len() {
            if &self.data[i].hash == hash {
                self.data.remove(i);
                break;
            }
        }
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.data.iter().filter(|x| &x.hash == hash).count() != 0
    }

    pub fn add(&mut self, hash: String, name: String, patch: String) {
        self.data.push(PkgMeta { hash, name, patch });
    }

    pub fn iter(&self) -> impl Iterator<Item = &PkgMeta> {
        self.data.iter()
    }

    pub async fn flush() {}

    pub fn flush_sync() {}
}
