use super::{ConnectionStatus, PkgCache, PkgDir, PkgMeta};
use reqwest::header::HeaderMap;
use reqwest::header::HeaderValue;
use reqwest::{
    blocking::{
        multipart::{Form, Part},
        Client,
    },
    StatusCode,
};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;

pub struct PkgClient {
    client: Client,
    ip: String,
    port: u16,
    dir: PkgDir,
}

impl PkgClient {
    pub fn new(dir: PkgDir, addr: &SocketAddr) -> PkgClient {
        PkgClient {
            client: Client::new(),
            ip: addr.ip().to_string(),
            port: addr.port(),
            dir,
        }
    }

    pub fn upload(&self, cache: &PkgCache, hash: String) -> Result<(), ()> {
        let route = format!("http://{}:{}/upload", self.ip, self.port);

        let pkg_meta = cache.get(&hash).ok_or(())?;
        let mut headers = HeaderMap::new();

        let pkg_name = HeaderValue::from_bytes(pkg_meta.name.as_bytes()).map_err(|_| ())?;
        headers.insert(super::NAME_HEADER, pkg_name);

        let pkg_patch = HeaderValue::from_bytes(pkg_meta.patch.as_bytes()).map_err(|_| ())?;
        headers.insert(super::PATCH_HEADER, pkg_patch);

        let path = self
            .dir
            .get_pkg_path(&hash)
            .expect("Hash not valid to create path");

        let Ok(part) = Part::file(&path) else { return Err(()) };
        let Ok(part) = part.file_name(hash).mime_str("application/octet-stream") else { return Err(()) };
        let form = Form::new().part("upload", part);

        let Ok(res) = self.client.post(route).headers(headers).multipart(form).send() else {
            return Err(());
        };

        if res.status() != StatusCode::OK {
            return Err(());
        }
        Ok(())
    }

    pub fn download(&self, cache: &mut PkgCache, hash: String) -> Result<(), ()> {
        let route = format!("http://{}:{}/download/{}", self.ip, self.port, &hash);
        let path = self
            .dir
            .get_pkg_path(&hash)
            .expect("hash not valid to create path");

        let response = self.client.get(route).send().map_err(|_| ())?;

        // validate that the download has a name
        let pkg_name = String::from(
            response
                .headers()
                .get(super::NAME_HEADER)
                .ok_or(())?
                .to_str()
                .map_err(|_| ())?,
        );

        // and it has a patch
        let pkg_patch = String::from(
            response
                .headers()
                .get(super::PATCH_HEADER)
                .ok_or(())?
                .to_str()
                .map_err(|_| ())?,
        );

        let bytes = response.bytes().map_err(|_| ())?;

        // make sure that the file is actually valid
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash_string = format!("{:x}", hasher.finalize());

        if &hash_string != &hash {
            return Err(());
        }

        let mut file = File::create(&path).map_err(|_| ())?;
        if let Err(_) = file.write_all(&bytes) {
            return Err(());
        }

        cache.add(PkgMeta {
            hash: hash_string,
            name: pkg_name,
            patch: pkg_patch,
        });

        Ok(())
    }

    pub fn get_status(&self) -> Result<ConnectionStatus, ()> {
        let route = format!("http://{}:{}/status", self.ip, self.port);
        let res = self.client.get(route).send().map_err(|_| ())?;
        let text = res.json::<ConnectionStatus>().map_err(|_| ())?;
        Ok(text)
    }

    pub fn activate(&self, hash: &str) -> Result<(), ()> {
        let route = format!("http://{}:{}/activate/{}", self.ip, self.port, hash);
        match self.client.post(route).send() {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    pub fn deactivate(&self, hash: &str) -> Result<(), ()> {
        let route = format!("http://{}:{}/deactivate/{}", self.ip, self.port, hash);
        match self.client.post(route).send() {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    pub fn get_active(&self) -> Result<Option<PkgMeta>, ()> {
        let route = format!("http://{}:{}/get-active", self.ip, self.port);
        let res = match self.client.get(route).send() {
            Ok(res) => res,
            Err(_) => return Err(()),
        };

        res.json::<Option<PkgMeta>>().map_err(|_| ())
    }

    pub fn list(&self) -> Result<Vec<PkgMeta>, ()> {
        let route = format!("http://{}:{}/list", self.ip, self.port);
        let res = match self.client.get(route).send() {
            Ok(res) => res,
            Err(_) => return Err(()),
        };

        let hashes: Vec<PkgMeta> = match res.json() {
            Ok(hashes) => hashes,
            Err(_) => return Err(()),
        };

        Ok(hashes)
    }
}
