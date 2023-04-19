use super::{PkgCache, PkgDir, ActivePkg};
use reqwest::{
    multipart::{Form, Part},
    Body, Client,
};
use sha2::{Digest, Sha256};
use tokio::fs::{self, File};
use tokio::io::AsyncWriteExt;
use tokio_util::codec::{BytesCodec, FramedRead};

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

    pub async fn upload(&self, hash: String) -> Result<(), ()> {
        let route = format!("http://{}:{}/upload", self.ip, self.port);
        let path = self
            .dir
            .get_pkg_path(&hash)
            .expect("Hash not valid to create path");

        let file = match File::open(path).await {
            Ok(file) => file,
            Err(_) => return Err(()),
        };

        let stream = FramedRead::new(file, BytesCodec::new());
        let body = Body::wrap_stream(stream);
        let part = match Part::stream(body)
            .file_name(hash)
            .mime_str("application/octet-stream")
        {
            Ok(part) => part,
            Err(_) => return Err(()),
        };
        let form = Form::new().part("upload", part);

        let _ = match self.client.post(route).multipart(form).send().await {
            Ok(res) => res,
            Err(_) => return Err(()),
        };

        Ok(())
    }

    pub async fn download(&self, cache: &mut PkgCache, hash: String) -> Result<(), ()> {
        let route = format!("http://{}:{}/download/{}", self.ip, self.port, &hash);
        let path = self
            .dir
            .get_pkg_path(&hash)
            .expect("Hash not valid to create path");

        let bytes = match self.client.get(route).send().await {
            Ok(res) => match res.bytes().await {
                Ok(bytes) => bytes,
                Err(_) => return Err(()),
            },
            Err(_) => return Err(()),
        };

        let mut file = match File::create(&path).await {
            Ok(file) => file,
            Err(_) => return Err(()),
        };

        if let Err(_) = file.write_all(&bytes).await {
            return Err(());
        }

        // make sure that the file is actually valid
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let hash_string = format!("{:x}", hasher.finalize());

        if &hash_string != &hash {
            fs::remove_file(path)
                .await
                .expect("Could not remove invalid file");

            return Err(());
        }

        cache.add(hash);
        return Ok(());
    }

    pub async fn activate(&self, hash: &str) -> Result<(), ()> {
        let route = format!("http://{}:{}/activate/{}", self.ip, self.port, hash);
        match self.client.post(route).send().await {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    pub async fn deactivate(&self, hash: &str) -> Result<(), ()> {
        let route = format!("http://{}:{}/deactivate/{}", self.ip, self.port, hash);
        match self.client.post(route).send().await {
            Ok(_) => Ok(()),
            Err(_) => Err(())
        }
    }

    pub async fn get_active(&self) -> Result<Option<String>, ()> {
        let route = format!("http://{}:{}/get-active", self.ip, self.port);
        let res = match self.client.get(route).send().await {
            Ok(res) => res,
            Err(_) => return Err(())
        };

        let active = match res.json::<ActivePkg>().await {
            Ok(active) => active,
            Err(_) => return Err(())
        };

        Ok(active.hash)
    }

    pub async fn list(&self) -> Result<Vec<String>, ()> {
        let route = format!("http://{}:{}/list", self.ip, self.port);
        let res = match self.client.get(route).send().await {
            Ok(res) => res,
            Err(_) => return Err(()),
        };

        let hashes: Vec<String> = match res.json().await {
            Ok(hashes) => hashes,
            Err(_) => return Err(()),
        };

        Ok(hashes)
    }
}
