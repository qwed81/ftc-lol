use super::mod_fs::{self, EntryVerificationLock, ModDir, EntryAddError};
use super::stream_util::{self, FileTransferError};
use super::{
    ConnectionHeader, ExtendedModEntry, ModEntry, ModEntryState, ServerStateUpdateMessage,
    ServerStateUpdateRequest,
};

use tokio::fs::File;
use tokio::io;
use tokio::net::{tcp::{OwnedWriteHalf, OwnedReadHalf}, TcpStream, ToSocketAddrs};

pub struct UpdateReceiver {
    reader: OwnedReadHalf,
}

impl UpdateReceiver {
    pub async fn next(&mut self) -> Option<Vec<ExtendedModEntry>> {
        let message: ServerStateUpdateMessage;
        message = match stream_util::read_message(&mut self.reader).await {
            Ok(message) => message,
            Err(_) => return None,
        };

        Some(message.server_mods)
    }
}

pub struct RequestSender {
    writer: OwnedWriteHalf,
}

impl RequestSender {
    pub async fn request_set_mod_state(
        &mut self,
        entry: ModEntry,
        new_state: ModEntryState,
    ) -> io::Result<()> {
        let request = ServerStateUpdateRequest {
            entry,
            requested_state: new_state,
        };

        stream_util::write_message(&mut self.writer, &request).await
    }
}

pub async fn connect(ip_addr: impl ToSocketAddrs) -> io::Result<(RequestSender, UpdateReceiver)> {
    let stream = TcpStream::connect(ip_addr).await?;
    let (reader, mut writer) = stream.into_split();
    let header = ConnectionHeader::Subscribe;
    stream_util::write_message(&mut writer, &header).await?;

    let update_receiver = UpdateReceiver {
        reader
    };
    let request_sender = RequestSender {
        writer,
    };
    Ok((request_sender, update_receiver))
}

pub struct FileDownload<'a> {
    stream: TcpStream,
    downloads: Vec<ModEntry>,
    download_index: usize,
    mod_dir: &'a ModDir,
}

impl<'a> FileDownload<'a> {
    pub fn peek_next(&self) -> Option<&ModEntry> {
        if self.download_index < self.downloads.len() {
            Some(&self.downloads[self.download_index])
        } else {
            None
        }
    }

    pub async fn download_next(&mut self) -> Result<EntryVerificationLock, FileTransferError> {
        if self.download_index >= self.downloads.len() {
            panic!("Called download next when there is no more downloads");
        }

        let entry = self.downloads[self.download_index].clone();
        let hash = &entry.hash;
        let file_len = entry.file_len;
        let entry_path = self.mod_dir.create_entry_path(hash);
        let mut file = File::create(&entry_path).await?;

        stream_util::copy_stream_and_verify_hash(&mut self.stream, &mut file, file_len, hash)
            .await?;

        mod_fs::write_metadata(self.mod_dir, &entry).await?;
        let lock = match mod_fs::verify_can_add_entry(self.mod_dir, entry).await {
            Ok(lock) => lock,
            Err(EntryAddError::NoEntry) => panic!("Mod was not saved"),
            Err(EntryAddError::NoMetadata) => panic!("Metadata was not saved"),
            Err(EntryAddError::IO(e)) => return Err(FileTransferError::IO(e))
        };

        self.download_index += 1;
        Ok(lock)
    }
}

pub async fn download<'a>(
    ip_addr: impl ToSocketAddrs,
    mod_dir: &'a ModDir,
    downloads: Vec<ModEntry>,
) -> io::Result<FileDownload<'a>> {
    let mut stream = TcpStream::connect(ip_addr).await?;
    let header = ConnectionHeader::Download;
    stream_util::write_message(&mut stream, &header).await?;
    stream_util::write_message(&mut stream, &downloads).await?;

    Ok(FileDownload {
        downloads,
        download_index: 0,
        mod_dir,
        stream,
    })
}

pub struct FileUpload<'a> {
    stream: TcpStream,
    uploads: Vec<ModEntry>,
    upload_index: usize,
    mod_dir: &'a ModDir,
}

impl<'a> FileUpload<'a> {
    pub fn peek_next(&self) -> Option<&ModEntry> {
        if self.upload_index < self.uploads.len() {
            Some(&self.uploads[self.upload_index])
        } else {
            None
        }
    }

    pub async fn upload_next(&mut self) -> io::Result<()> {
        if self.upload_index >= self.uploads.len() {
            panic!("Called upload next when there were no more to upload");
        }

        let hash = &self.uploads[self.upload_index].hash;
        let file_len = self.uploads[self.upload_index].file_len;
        let entry_path = self.mod_dir.create_entry_path(hash);
        let file = File::open(&entry_path).await?;

        let copy_result =
            stream_util::copy_stream_and_verify_hash(file, &mut self.stream, file_len, hash).await;
        match copy_result {
            Ok(_) => (),
            Err(FileTransferError::InvalidHash) => panic!("File hash does not match metadata"),
            Err(FileTransferError::IO(e)) => return Err(e),
        }

        self.upload_index += 1;
        Ok(())
    }
}

pub async fn upload<'a>(
    ip_addr: impl ToSocketAddrs,
    mod_dir: &'a ModDir,
    uploads: Vec<ModEntry>,
) -> io::Result<FileUpload<'a>> {
    let mut stream = TcpStream::connect(ip_addr).await?;
    let header = ConnectionHeader::Upload;
    stream_util::write_message(&mut stream, &header).await?;
    stream_util::write_message(&mut stream, &uploads).await?;

    Ok(FileUpload {
        uploads,
        upload_index: 0,
        mod_dir,
        stream,
    })
}
