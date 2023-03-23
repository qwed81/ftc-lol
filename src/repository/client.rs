use super::stream_util::{self, MessageError};
use super::{
    ConnectionHeader, ExtendedModEntry, ModEntry, ServerStateUpdateMessage,
    ServerStateUpdateRequest, ModEntryState
};

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::io;
use tokio::net::{
    tcp::OwnedWriteHalf,
    TcpStream, ToSocketAddrs,
};
use tokio::sync::mpsc::{self, Receiver};

pub struct UpdateReceiver<T> {
    rx: Receiver<T>,
    should_close: Arc<AtomicBool>,
}
impl<T> UpdateReceiver<T> {
    pub async fn next(&mut self) -> T {
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
        requested_state: ModEntryState,
    ) -> io::Result<()> {
        let request = ServerStateUpdateRequest { entry, requested_state };
        match stream_util::write_message(&mut self.writer, &request).await {
            Ok(_) => Ok(()),
            Err(e) => match e {
                MessageError::Format => panic!("format is wrong while writing message"),
                MessageError::IO(e) => return Err(e),
            },
        }
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

pub async fn connect(
    ip_addr: impl ToSocketAddrs,
) -> io::Result<(RequestSender, UpdateReceiver<StateUpdate>)> {
    let stream = TcpStream::connect(ip_addr).await?;
    let (mut reader, mut writer) = stream.into_split();
    let should_close = Arc::new(AtomicBool::new(false));
    let should_close_clone = Arc::clone(&should_close);
    let (tx, rx) = mpsc::channel(100);

    let header = ConnectionHeader::Subscribe;
    if let Err(e) = stream_util::write_message(&mut writer, &header).await {
        match e {
            MessageError::Format => panic!(""),
            MessageError::IO(e) => return Err(e),
        }
    }

    tokio::spawn(async move {
        tx.send(StateUpdate::Connected).await.unwrap();
        while should_close_clone.load(Ordering::Relaxed) == false {
            let message: ServerStateUpdateMessage =
                match stream_util::read_message(&mut reader).await {
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
    Connected,
    FileStarted { id: u64, entry: ModEntry },
    FileUpdated { id: u64, progress: u32 },
    FileFinished { id: u64 },
    Disconnected,
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

pub async fn upload() {}
*/
