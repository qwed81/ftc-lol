use crate::pkg::ConnectionStatus;
use crate::pkg::PkgMeta;
use crate::pkg::{client::PkgClient, PkgCache, PkgDir};
use crate::segment_table;
use memmap2::MmapOptions;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

const HASH_DISPLAY_LEN: usize = 10;
pub fn fmt_pkg_parts(hash: &str, name: &str, patch: &str) -> String {
    format!("{} ({}:{})", &hash[0..HASH_DISPLAY_LEN], name, patch)
}

pub fn fmt_pkg(meta: &PkgMeta) -> String {
    fmt_pkg_parts(&meta.hash, &meta.name, &meta.patch)
}

pub fn import(dir: &PkgDir, cache: &mut PkgCache, pkg_name: String, path: &Path) {
    let Ok(mut file) = File::open(path) else {
        println!("could not open {:?}", path);
        println!("import failed");
        return;
    };

    let mem = unsafe { MmapOptions::new().map(&file) }.expect("could mmap file");
    let mut hasher = Sha256::new();
    hasher.update(&mem);
    let hash_string = format!("{:x}", hasher.finalize());

    // we can unwrap because a hash + path should always result in a valid pkg_path
    let new_path = dir.get_pkg_path(&hash_string).unwrap();
    let Ok(mut copy_to) = File::create(&new_path) else {
        println!("could not create new file");
        println!("import failed");
        return;
    };

    if let Err(_) = io::copy(&mut file, &mut copy_to) {
        println!("could not copy to new file");
        println!("import failed");
        return;
    }

    println!(
        "import succeeded as {}",
        fmt_pkg_parts(&hash_string, &pkg_name, &crate::get_current_patch())
    );

    cache.add(PkgMeta {
        hash: hash_string,
        name: pkg_name,
        patch: crate::get_current_patch(),
    });

    if let Err(_) = cache.flush_blocking() {
        println!("could not save package metadata");
    }
}

fn recursive_add_dir(path: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(&path)? {
        let entry = entry.unwrap();

        if entry.file_type().unwrap().is_dir() {
            recursive_add_dir(&entry.path(), files)?;
        } else {
            files.push(entry.path());
        }
    }

    Ok(())
}

pub fn merge(dir: &PkgDir, cache: &mut PkgCache, pkg_name: String, paths: Vec<&str>) {
    let mod_path = env::var("MOD_PATH").expect("MOD_PATH environment variable required");

    // we need to append all paths to the mod_path
    let mut mod_path = PathBuf::from(mod_path);
    let mut path_bufs = Vec::new();
    for path in paths {
        mod_path.push(path);
        mod_path.push("WAD");

        if let Err(_) = recursive_add_dir(&mod_path, &mut path_bufs) {
            println!("could not add dir {:?}", &mod_path);
            return;
        }

        // pop off so same PathBuf can be used for next str
        mod_path.pop();
        mod_path.pop();
    }

    let Ok(seg_table) = segment_table::from_fantome_wad_list(&path_bufs) else {
        println!("error while creating package");
        return;
    };

    // hash the seg table
    let mut hasher = Sha256::new();
    hasher.update(&seg_table);
    let hash_string = format!("{:x}", hasher.finalize());

    if cache.contains_hash(&hash_string) {
        println!("package is already downloaded");
        println!("package hash is {}", &hash_string[0..HASH_DISPLAY_LEN]);
        return;
    }

    // we can unwrap because a hash + path should always result in a valid pkg_path
    let new_path = dir.get_pkg_path(&hash_string).unwrap();
    if let Err(_) = fs::write(new_path, seg_table) {
        println!("could not write seg table to file");
        println!("merge failed");
        return;
    }

    println!(
        "merge succeeded as {}",
        fmt_pkg_parts(&hash_string, &pkg_name, &crate::get_current_patch())
    );

    cache.add(PkgMeta {
        hash: hash_string,
        name: pkg_name,
        patch: crate::get_current_patch(),
    });

    if let Err(_) = cache.flush_blocking() {
        println!("could not save package metadata");
    }
}

enum PrefixedHash {
    Valid(String),
    TooMany,
    NotAny,
}

fn get_prefixed_hash<'a, I>(hash: &str, iter: I, list_name: &str) -> PrefixedHash
where
    I: Iterator<Item = &'a PkgMeta> + 'a,
{
    let mut count = 0;
    let mut selected = None;
    for h in iter {
        let h = &h.hash;
        if h.starts_with(hash) {
            selected = Some(String::from(h));
            count += 1;
        }
        if count > 1 {
            println!("multiple hashes match in {}", list_name);
            return PrefixedHash::TooMany;
        }
    }

    match selected {
        Some(selected) => PrefixedHash::Valid(selected),
        None => {
            println!("no hashes match in {}", list_name);
            PrefixedHash::NotAny
        }
    }
}

pub fn upload(client: &PkgClient, cache: &PkgCache, hash: &str) {
    let PrefixedHash::Valid(hash) = get_prefixed_hash(&hash, cache.iter(), "local packages") else {
        println!("could not upload");
        return;
    };

    if let Err(_) = client.upload(cache, String::from(hash)) {
        println!("upload failed");
    }
}

pub fn download(client: &PkgClient, cache: &mut PkgCache, hash: &str) {
    let Ok(remote_hashes) = client.list() else {
        println!("could not list remote packages");
        return;
    };

    let PrefixedHash::Valid(hash) = get_prefixed_hash(&hash, remote_hashes.iter(), "remote packages") else {
        println!("could not download");
        return;
    };

    if let Err(_) = client.download(cache, String::from(hash)) {
        println!("download failed");
    }

    if let Err(_) = cache.flush_blocking() {
        println!("could not save package metadata");
    }
}

pub fn remove(dir: &PkgDir, cache: &mut PkgCache, hash: &str) {
    let PrefixedHash::Valid(hash) = get_prefixed_hash(&hash, cache.iter(), "local packages") else {
        println!("could not remove");
        return;
    };

    let path = dir.get_pkg_path(&hash).unwrap();
    if let Err(_) = fs::remove_file(&path) {
        println!("could not remove file, io error");
        return;
    }

    cache.remove(&hash);
    if let Err(_) = cache.flush_blocking() {
        println!("could not remove package meta");
    }
}

pub fn set(client: &PkgClient, hash: &str, active_text: &str) {
    let Ok(remote_hashes) = client.list() else {
        println!("could not list remote packages");
        return;
    };

    let PrefixedHash::Valid(hash) =
        get_prefixed_hash(&hash, remote_hashes.iter(), "remote packages") else {
            println!("could not set activation");
            return;
        };

    let result = match active_text {
        "active" => client.activate(&hash),
        "inactive" => client.deactivate(&hash),
        _ => {
            println!("only active and inactive are allowed as options");
            Err(())
        }
    };

    if result.is_err() {
        println!("setting activation failed");
    }
}

pub fn print_meta_list<'a, I>(items: I)
where
    I: Iterator<Item = &'a PkgMeta> + 'a,
{
    let mut count = 0;
    for meta in items {
        println!("{}", fmt_pkg_parts(&meta.hash, &meta.name, &meta.patch));
        count += 1;
    }

    if count == 0 {
        println!("there are no packages");
    }
}

pub fn print_status(client: &PkgClient) {
    let start = Instant::now();
    let status_result = client.get_status();
    let time_taken = (Instant::now() - start).as_millis();

    match status_result {
        Ok(status) => match status {
            ConnectionStatus::Connected => println!("status: OK, delay: {}ms", time_taken),
        },
        Err(_) => println!("the server could not be reached"),
    }
}
