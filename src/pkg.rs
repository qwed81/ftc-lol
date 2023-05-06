use axum::http::HeaderName;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

pub mod client;
pub mod server;

const NAME_HEADER: HeaderName = HeaderName::from_static("x-pkg-name");
const PATCH_HEADER: HeaderName = HeaderName::from_static("x-pkg-patch");

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

#[derive(Clone, Deserialize, Serialize)]
pub struct PkgMeta {
    pub hash: String,
    pub name: String,
    pub patch: String,
}

pub struct PkgCache {
    data: Vec<PkgMeta>,
    dir: PkgDir,
}

impl PkgCache {
    pub fn from_dir_blocking(dir: PkgDir) -> io::Result<PkgCache> {
        let meta_path = dir.get_meta_path();

        match fs::read(&meta_path) {
            Ok(data) => {
                let meta = serde_json::from_slice(&data).expect("data is corrupted");
                return Ok(PkgCache { dir, data: meta });
            }
            Err(e) => {
                // if it errored because the file does not exist, just create it
                if let io::ErrorKind::NotFound = e.kind() {
                    let meta: Vec<PkgMeta> = Vec::new();
                    let data = serde_json::to_vec(&meta).expect("could not serialize");
                    fs::write(&meta_path, data)?;
                    return Ok(PkgCache { dir, data: meta });
                } else {
                    return Err(e);
                }
            }
        }
    }

    pub fn remove(&mut self, hash: &str) {
        for i in 0..self.data.len() {
            if &self.data[i].hash == hash {
                self.data.remove(i);
                break;
            }
        }
    }

    pub fn contains_hash(&self, hash: &str) -> bool {
        self.data.iter().filter(|x| &x.hash == hash).count() != 0
    }

    pub fn get<'a>(&'a self, hash: &str) -> Option<&'a PkgMeta> {
        self.data.iter().filter(|x| &x.hash == hash).next()
    }

    pub fn hashes(&self) -> impl Iterator<Item = &String> {
        self.data.iter().map(|x| &x.hash)
    }

    pub fn add(&mut self, pkg: PkgMeta) {
        self.data.push(pkg);
    }

    pub fn iter(&self) -> impl Iterator<Item = &PkgMeta> {
        self.data.iter()
    }

    pub fn flush_blocking(&self) -> io::Result<()> {
        let path = self.dir.get_meta_path();
        let items: Vec<&PkgMeta> = self.iter().collect();
        let data = serde_json::to_vec(&items).expect("meta could not be serialized");
        fs::write(&path, data)
    }
}
