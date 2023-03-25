use super::stream_util::{self, MessageError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs::{self, File};
use tokio::io::{self, SeekFrom, AsyncSeekExt};

use super::ModEntry;

pub struct ModDir {
    root_path: PathBuf,
    meta_path: PathBuf,
    entry_path: PathBuf,
}

impl ModDir {
    pub fn new(root_path: impl AsRef<Path>) -> ModDir {
        let root_path = PathBuf::from(root_path.as_ref());
        let mut meta_path = root_path.clone();
        let mut entry_path = root_path.clone();
        meta_path.push("meta");
        entry_path.push("mods");

        ModDir {
            root_path,
            meta_path,
            entry_path,
        }
    }

    pub fn get_root(&self) -> &Path {
        &self.root_path
    }

    pub fn get_meta_root(&self) -> &Path {
        &self.meta_path
    }

    pub fn get_entry_root(&self) -> &Path {
        &self.entry_path
    }

    pub fn create_meta_path(&self, hash: &str) -> PathBuf {
        let mut path = self.meta_path.clone();
        path.push(hash);
        path
    }

    pub fn create_entry_path(&self, hash: &str) -> PathBuf {
        let mut path = self.entry_path.clone();
        path.push(hash);
        path
    }
}

pub struct EntryCache {
    entries: HashMap<String, ModEntry>,
    current_iteration: u64,
}

impl EntryCache {
    pub async fn load_from_dir(dir: &ModDir) -> io::Result<EntryCache> {
        let meta_path = dir.get_meta_root();
        create_dir_if_missing(meta_path).await?;
        let mut meta_dir = fs::read_dir(meta_path).await?;
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

        let entry_path = dir.get_entry_root();
        create_dir_if_missing(entry_path).await?;
        let mut entry_dir = fs::read_dir(entry_path).await?;
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

        Ok(EntryCache {
            entries: finalized_cache,
            current_iteration: 0,
        })
    }

    pub fn get_current_iteration(&self) -> u64 {
        self.current_iteration
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.entries.contains_key(hash)
    }

    pub fn entries(&self) -> impl Iterator<Item = &ModEntry> {
        self.entries.values()
    }

    pub fn add_entry(&mut self, lock: EntryVerificationLock) {
        self.entries.insert(lock.entry.hash.clone(), lock.entry);
        self.current_iteration += 1;
    }
}

// lock that says that it is verified that it can be added to the
// cache, we can't add directly to the cache because it will probably
// be in a mutex, and we require io to verify
#[must_use]
pub struct EntryVerificationLock {
    entry: ModEntry,
}

#[derive(Debug)]
pub enum EntryAddError {
    NoEntry,
    NoMetadata,
    IO(io::Error),
}

impl From<io::Error> for EntryAddError {
    fn from(err: io::Error) -> EntryAddError {
        EntryAddError::IO(err)
    }
}

// should be called with the information from the entry_cache, outside of the impl
// because it does IO, and the cache will most likley need to be wrapped in a mutex,
// so we can still do IO without locking up the mutex. This returns a lock so that
// it must be verified before an entry can be added
pub async fn verify_can_add_entry(
    dir: &ModDir,
    entry: ModEntry
) -> Result<EntryVerificationLock, EntryAddError> {
    if fs::try_exists(dir.create_entry_path(&entry.hash)).await? == false {
        return Err(EntryAddError::NoEntry);
    }
    if fs::try_exists(dir.create_meta_path(&entry.hash)).await? == false {
        return Err(EntryAddError::NoMetadata);
    }

    Ok(EntryVerificationLock { entry })
}

pub async fn write_metadata(dir: &ModDir, entry: &ModEntry) -> io::Result<()> {
    let meta_path = dir.create_meta_path(&entry.hash);
    let meta_file = fs::File::create(meta_path).await?;
    stream_util::write_message(meta_file, &entry).await?;

    Ok(())
}

pub async fn import_external_entry(dir: &ModDir, external_path: &Path, name: String) -> io::Result<EntryVerificationLock> {
    let mut file = File::open(external_path).await?;
    let file_len = file.metadata().await?.len();
    let hash = stream_util::hash_full_stream(&mut file).await?;
    file.seek(SeekFrom::Start(0)).await?;

    let new_path = dir.create_entry_path(&hash);
    let mut new_file = File::create(&new_path).await?;

    stream_util::copy_stream_and_verify_hash(&mut file, &mut new_file, file_len, &hash)
        .await
        .unwrap();

    let entry = ModEntry {
        hash, name, file_len
    };

    write_metadata(dir, &entry).await?;
    let lock = match verify_can_add_entry(dir, entry).await {
        Ok(lock) => lock,
        Err(EntryAddError::IO(e)) => return Err(e),
        Err(e) => panic!("could not verify file, error: {:?}", e)
    };

    Ok(lock)
}

async fn create_dir_if_missing(path: &Path) -> io::Result<()> {
    if fs::try_exists(path).await? == false {
        fs::DirBuilder::new().create(path).await?;
    }
    Ok(())
}
