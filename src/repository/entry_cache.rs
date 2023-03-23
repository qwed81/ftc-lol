use super::stream_util::{self, MessageError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs::{self, File};
use tokio::io;

use super::ModEntry;

pub struct EntryCache {
    entries: HashMap<String, ModEntry>,
    root_path: PathBuf,
    current_iteration: u64
}

async fn create_dir_if_missing(path: &Path) -> io::Result<()> {
    if fs::try_exists(path).await? == false {
        fs::DirBuilder::new().create(path).await?;
    }
    Ok(())
}

impl EntryCache {
    pub async fn from_dir(path: impl AsRef<Path>) -> io::Result<EntryCache> {
        let mut path = PathBuf::from(path.as_ref());
        path.push("meta");
        create_dir_if_missing(&path).await?;
        let mut meta_dir = fs::read_dir(&path).await?;
        let mut meta_entries = HashMap::new();
        while let Some(meta) = meta_dir.next_entry().await? {
            let mut meta_file = File::open(meta.path()).await?;
            let data: ModEntry = match stream_util::read_message(&mut meta_file).await {
                Ok(entry) => entry,
                Err(MessageError::Format) => panic!("Corrupt file"),
                Err(MessageError::IO(e)) => return Err(e),
            };
            meta_entries.insert(data.hash.clone(), data);
        }
        path.pop();

        path.push("mods");
        create_dir_if_missing(&path).await?;
        let mut entry_dir = fs::read_dir(&path).await?;
        let mut finalized_cache = HashMap::new();
        while let Some(entry) = entry_dir.next_entry().await? {
            let hash = entry.file_name();
            let hash = hash.to_str().unwrap();
            // only insert the keys and values that are in both
            let (key, value) = match meta_entries.remove_entry(hash) {
                Some(tuple) => tuple,
                None => panic!("File without matching metadata, hash: {}", hash),
            };
            finalized_cache.insert(key, value);
        }

        if meta_entries.is_empty() == false {
            let hash = &meta_entries.iter().next().unwrap().1.hash;
            panic!("Metadata file without matching entry, hash: {}", hash);
        }
        path.pop();

        Ok(EntryCache {
            entries: HashMap::new(),
            root_path: path,
            current_iteration: 0
        })
    }

    pub fn get_current_iteration(&self) -> u64 {
        self.current_iteration
    }

    pub fn create_meta_path(&self, hash: &str) -> PathBuf {
        let mut path = self.root_path.clone();
        path.push("meta");
        path.push(hash);
        path
    }

    pub fn create_entry_path(&self, hash: &str) -> PathBuf {
        let mut path = self.root_path.clone();
        path.push("mods");
        path.push(hash);
        path
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.entries.contains_key(hash)
    }

    pub fn entries(&self) -> impl Iterator<Item=&ModEntry> {
        self.entries.values()
    }

    pub fn add_entry(&mut self, entry: ModEntry) {
        self.entries.insert(entry.hash.clone(), entry);
        self.current_iteration += 1;
    }

}

// should be called with the information from the entry_cache, outside of the impl
// because it does IO, and the cache will most likley need to be wrapped in a mutex,
// so we can still do IO without locking up the mutex
pub async fn verify_can_add_entry(meta_path: &Path, entry_path: &Path) -> Result<(), EntryAddError> {
    if fs::try_exists(entry_path).await? == false {
        return Err(EntryAddError::NoEntry);
    }
    if fs::try_exists(meta_path).await? == false {
        return Err(EntryAddError::NoMetadata);
    }
    Ok(())
}

pub async fn write_metadata(meta_path: &Path, entry: &ModEntry) -> io::Result<()> {
    let meta_file = fs::File::open(meta_path).await?;
    match stream_util::write_message(meta_file, &entry).await {
        Ok(_) => (),
        Err(MessageError::IO(e)) => return Err(e),
        Err(MessageError::Format) => panic!("Invalid format when writing entry"),
    };
    Ok(())
}


#[derive(Debug)]
pub enum EntryAddError {
    NoEntry,
    NoMetadata,
    IO(io::Error)
}

impl From<io::Error> for EntryAddError {
    fn from(err: io::Error) -> EntryAddError {
        EntryAddError::IO(err)
    }
}



