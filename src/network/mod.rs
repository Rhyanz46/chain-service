pub mod client;
pub mod server;
pub mod id_manager;

pub use client::FileTransferClient;
pub use server::FileTransferServer;
pub use id_manager::NetworkIdManager;

use anyhow::Result;
use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

/// Read file in chunks for streaming
pub async fn read_file_chunks<P: AsRef<Path>>(
    path: P,
    chunk_size: usize,
) -> Result<Vec<Vec<u8>>> {
    let mut file = File::open(path).await?;
    let mut chunks = Vec::new();
    let mut buffer = vec![0u8; chunk_size];

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }

        chunks.push(buffer[..n].to_vec());
    }

    Ok(chunks)
}

/// Calculate file checksum (SHA-256)
pub async fn calculate_checksum<P: AsRef<Path>>(path: P) -> Result<String> {
    let mut file = File::open(path).await?;
    let mut hasher = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buffer = vec![0u8; 8192];

    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finish().as_ref()))
}
