use super::{PkgCache, PkgDir, ActivePkg};
use reqwest::blocking::{
    multipart::{Form, Part}, Client,
};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;

pub struct PkgClient {
    client: Client,
    ip: String,
    port: u16,
    dir: PkgDir,
}

impl PkgClient {
    pub fn new(dir: PkgDir, ip: String, port: u16) -> PkgClient {
        PkgClient {
            client: Client::new(),
            ip,
            port,
            dir,
        }
    }

    pub fn upload(&self, hash: String) -> Result<(), ()> {
        let route = format!("http://{}:{}/upload", self.ip, self.port);
        let path = self
            .dir
            .get_pkg_path(&hash)
            .expect("Hash not valid to create path");

        let part_result = match Part::file(&path) {
            Ok(part) => part,
            Err(_) => return Err(()),
        }.file_name(hash).mime_str("application/octet-stream");

        let part = match part_result {
            Ok(part) => part,
            Err(_) => return Err(())
        };

        let form = Form::new().part("upload", part);
        let _ = match self.client.post(route).multipart(form).send() {
            Ok(res) => res,
            Err(_) => return Err(()),
        };

        Ok(())
    }

    pub fn download(&self, cache: &mut PkgCache, hash: String) -> Result<(), ()> {
        let route = format!("http://{}:{}/download/{}", self.ip, self.port, &hash);
        let path = self
            .dir
            .get_pkg_path(&hash)
            .expect("Hash not valid to create path");

        let bytes = match self.client.get(route).send() {
            Ok(res) => match res.bytes() {
                Ok(bytes) => bytes,
                Err(_) => return Err(()),
            },
            Err(_) => return Err(()),
        };

        let mut file = match File::create(&path) {
            Ok(file) => file,
            Err(_) => return Err(()),
        };

        if let Err(_) = file.write_all(&bytes) {
            return Err(());
        }

        // make sure that the file is actually valid
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash_string = format!("{:x}", hasher.finalize());

        if &hash_string != &hash {
            fs::remove_file(path)
                .expect("Could not remove invalid file");

            return Err(());
        }

        cache.add(hash);
        return Ok(());
    }

    pub fn activate(&self, hash: &str) -> Result<(), ()> {
        let route = format!("http://{}:{}/activate/{}", self.ip, self.port, hash);
        match self.client.post(route).send() {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    pub fn deactivate(&self, hash: &str) -> Result<(), ()> {
        let route = format!("http://{}:{}/deactivate/{}", self.ip, self.port, hash);
        match self.client.post(route).send() {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    pub fn get_active(&self) -> Result<Option<String>, ()> {
        let route = format!("http://{}:{}/get-active", self.ip, self.port);
        let res = match self.client.get(route).send() {
            Ok(res) => res,
            Err(_) => return Err(())
        };

        let active = match res.json::<ActivePkg>() {
            Ok(active) => active,
            Err(_) => return Err(())
        };

        Ok(active.hash)
    }

    pub fn list(&self) -> Result<Vec<String>, ()> {
        let route = format!("http://{}:{}/list", self.ip, self.port);
        let res = match self.client.get(route).send() {
            Ok(res) => res,
            Err(_) => return Err(()),
        };

        let hashes: Vec<String> = match res.json() {
            Ok(hashes) => hashes,
            Err(_) => return Err(()),
        };

        Ok(hashes)
    }
}
