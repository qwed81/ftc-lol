use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Debug;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug)]
pub enum MessageError {
    Format,
    IO(io::Error),
}

impl From<io::Error> for MessageError {
    fn from(err: io::Error) -> MessageError {
        MessageError::IO(err)
    }
}

#[derive(Debug)]
pub enum FileTransferError {
    InvalidHash,
    IO(io::Error),
}

impl From<io::Error> for FileTransferError {
    fn from(err: io::Error) -> FileTransferError {
        FileTransferError::IO(err)
    }
}

pub async fn read_message<R: AsyncRead + Unpin, T: Debug + DeserializeOwned>(
    mut reader: R,
) -> Result<T, MessageError> {
    let len: u64 = reader.read_u64_le().await?;
    let len: usize = len.try_into().unwrap();
    let mut vec = Vec::with_capacity(len);

    // because the vector is of u8 (does not drop), as well as
    // the capacity is == len, this is ok
    unsafe { vec.set_len(len) };
    reader.read_exact(&mut vec).await?;
    let json = match String::from_utf8(vec) {
        Ok(json) => json,
        Err(_) => return Err(MessageError::Format),
    };

    let message = match serde_json::from_str(&json) {
        Ok(message) => message,
        Err(_) => return Err(MessageError::Format),
    };

    Ok(message)
}

pub async fn write_message<W: AsyncWrite + Unpin, T: Debug + Serialize>(
    mut writer: W,
    message: &T,
) -> Result<(), MessageError> {
    let mut vec = match serde_json::to_vec(message) {
        Ok(vec) => vec,
        Err(_) => return Err(MessageError::Format),
    };

    let len: u64 = vec.len().try_into().unwrap();
    // get the length as a little endian byte array
    let len_bytes = len.to_le_bytes();
    // prepend the 8 bytes to the beginning of the vector
    vec.splice(0..0, len_bytes);

    writer.write_all(&vec).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn hash_full_stream<R: AsyncRead + Unpin>(mut reader: R) -> Result<String, io::Error> {
    let mut buffer: [u8; 1024] = [0; 1024];
    let mut hasher = Sha256::new();

    let mut amt_read = 1;
    while amt_read != 0 {
        amt_read = reader.read(&mut buffer).await?;
        hasher.update(&buffer[0..amt_read]);
    }

    let hash = format!("{:x}", hasher.finalize());
    Ok(hash)
}

pub async fn copy_stream_and_verify_hash<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    file_len: u64,
    expected_hash: &str,
) -> Result<(), FileTransferError> {
    let mut buffer: [u8; 1024] = [0; 1024];
    let mut hasher = Sha256::new();

    let mut amt_read = 1;
    let mut amt_left = file_len;
    while amt_read != 0 && amt_left != 0 {
        let mut buffer_slice = if amt_left as usize >= buffer.len() {
            &mut buffer
        } else {
            &mut buffer[..amt_left as usize]
        };
        amt_read = reader.read(&mut buffer_slice).await?;
        hasher.update(&mut buffer_slice);
        writer.write_all(&mut buffer_slice).await?;
        writer.flush().await?;

        amt_left -= amt_read as u64;
    }

    if amt_left != 0 {
        let error = io::Error::new(io::ErrorKind::UnexpectedEof, "stream closed before full file could be read");
        return Err(FileTransferError::IO(error));
    }

    let actual_hash = format!("{:x}", hasher.finalize());
    if actual_hash != expected_hash {
        return Err(FileTransferError::InvalidHash);
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use serde::{Deserialize, Serialize};
    use std::io::{Cursor, Seek, SeekFrom};

    #[derive(Deserialize, Serialize, Debug)]
    struct TestMessage {
        val1: u32,
        val2: u64,
    }

    #[tokio::test]
    async fn send_message() {
        let message = TestMessage {
            val1: 30,
            val2: 220,
        };
        let mut buf: [u8; 4096] = [0; 4096];
        let mut cursor = Cursor::new(&mut buf[..]);
        super::write_message(&mut cursor, &message).await.unwrap();
        cursor.seek(SeekFrom::Start(0)).unwrap();

        let got_message: TestMessage = super::read_message(&mut cursor).await.unwrap();
        assert_eq!(message.val1, got_message.val1);
        assert_eq!(message.val2, got_message.val2);
        assert_ne!(message.val1, 31);
    }

    #[tokio::test]
    async fn hash_stream() {
        let mut string = String::new();
        for _ in 0..2049 {
            string.push('C');
        }

        let mut cursor = Cursor::new(string.as_bytes());
        let hash = super::hash_full_stream(&mut cursor).await.unwrap();
        assert_eq!(hash, "e7f7cdd084f6d43500b74811000b8c22d4196addafe0917be4de08ea397bfbae");
    }

    #[tokio::test]
    async fn send_file() {
        let mut src: Vec<u8> = (0..10_000).map(|b| (b & 0xFF) as u8).collect();
        let mut buf: Vec<u8> = vec![0; 10_000];

        let len = src.len() as u64;
        let mut read = Cursor::new(&mut src[..]);
        let mut write = Cursor::new(&mut buf[..]);

        // if hash_stream is not working, then this will not work
        let hash = super::hash_full_stream(&mut read).await.unwrap();
        read.seek(SeekFrom::Start(0)).unwrap();

        super::copy_stream_and_verify_hash(&mut read, &mut write, len, &hash)
            .await
            .unwrap();
        drop(write);

        assert_eq!(&buf, &src);
    }
}
