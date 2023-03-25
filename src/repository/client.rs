use super::mod_fs::ModDir;
use super::stream_util::{self, FileTransferError};
use super::{
    ConnectionHeader, ExtendedModEntry, ModEntry, ModEntryState, ServerStateUpdateMessage,
    ServerStateUpdateRequest,
};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::fs::File;
use tokio::io;
use tokio::net::{tcp::OwnedWriteHalf, TcpStream, ToSocketAddrs};
use tokio::sync::mpsc::{self, Receiver};

pub struct UpdateReceiver {
    rx: Receiver<StateUpdate>,
    should_close: Arc<AtomicBool>,
}
impl UpdateReceiver {
    pub async fn next(&mut self) -> StateUpdate {
        match self.rx.recv().await {
            Some(val) => val,
            None => panic!("Continued to call next after disconnected"),
        }
    }

    pub fn notify_should_close(&mut self) {
        self.should_close.store(true, Ordering::Relaxed);
    }
}

pub struct RequestSender {
    writer: OwnedWriteHalf,
    should_close: Arc<AtomicBool>,
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

    pub fn notify_should_close(&mut self) {
        self.should_close.store(true, Ordering::Relaxed);
    }
}

#[derive(Debug)]
pub enum StateUpdate {
    Connected,
    StateUpdate(Vec<ExtendedModEntry>),
    Disconnected,
}

pub async fn connect(ip_addr: impl ToSocketAddrs) -> io::Result<(RequestSender, UpdateReceiver)> {
    let stream = TcpStream::connect(ip_addr).await?;
    let (mut reader, mut writer) = stream.into_split();
    let should_close = Arc::new(AtomicBool::new(false));
    let should_close_clone = Arc::clone(&should_close);
    let (tx, rx) = mpsc::channel(100);

    let header = ConnectionHeader::Subscribe;
    stream_util::write_message(&mut writer, &header).await?;

    tokio::spawn(async move {
        tx.send(StateUpdate::Connected).await.unwrap();
        while should_close_clone.load(Ordering::Relaxed) == false {
            let message: ServerStateUpdateMessage;
            message = match stream_util::read_message(&mut reader).await {
                Ok(message) => message,
                Err(_) => break,
            };

            tx.send(StateUpdate::StateUpdate(message.server_mods))
                .await
                .unwrap();
        }
        tx.send(StateUpdate::Disconnected).await.unwrap();
    });

    let update_receiver = UpdateReceiver {
        rx,
        should_close: Arc::clone(&should_close),
    };
    let request_sender = RequestSender {
        writer,
        should_close,
    };
    Ok((request_sender, update_receiver))
}

#[derive(Debug)]
pub enum FileUpdate {
    Started,
    FileStarted { id: u64, entry: ModEntry },
    FileUpdated { id: u64, progress: u32 },
    FileFinished { id: u64 },
    Disconnected(io::Result<()>),
}

/*
pub async fn download(ip_addr: impl ToSocketAddrs) -> io::Result<UpdateReceiver<FileUpdate>> {
    let mut stream = TcpStream::connect(ip_addr).await?;
    let should_close = Arc::new(AtomicBool::new(false));
    let should_close_clone = Arc::clone(&should_close);
    let (tx, rx) = mpsc::channel(100);

    let header = ConnectionHeader::Download;
    stream_util::write_message(&mut stream, &header);

    Ok(UpdateReceiver { rx, should_close })
}
*/

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
    uploads: Vec<ModEntry>
) -> io::Result<FileUpload<'a>> {
    let mut stream = TcpStream::connect(ip_addr).await?;
    let header = ConnectionHeader::Download;
    stream_util::write_message(&mut stream, &header).await?;
    stream_util::write_message(&mut stream, &uploads).await?;

    Ok(FileUpload {
        uploads,
        upload_index: 0,
        mod_dir,
        stream,
    })
}
