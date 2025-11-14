use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;
use tonic::transport::Channel;
use tonic::{Request, metadata::MetadataValue};
use tracing::{debug, info};

use crate::grpc::file_transfer::{
    file_transfer_service_client::FileTransferServiceClient, AuthRequest, DownloadRequest,
    FileChunk, FileMetadata, ListFilesRequest, PingRequest,
};
use crate::pki::{CertificateManager, NodeIdentity};

/// File transfer client for connecting to remote nodes
pub struct FileTransferClient {
    identity: NodeIdentity,
    chunk_size: usize,
}

impl FileTransferClient {
    /// Create a new file transfer client
    pub fn new(identity: NodeIdentity, chunk_size: usize) -> Self {
        Self {
            identity,
            chunk_size,
        }
    }

    /// Connect to a remote node
    pub async fn connect(&self, address: &str) -> Result<FileTransferServiceClient<Channel>> {
        info!("Connecting to {}", address);

        let endpoint = format!("http://{}", address);
        let channel = Channel::from_shared(endpoint)?
            .connect()
            .await
            .context("Failed to connect to server")?;

        Ok(FileTransferServiceClient::new(channel))
    }

    /// Authenticate with a remote node
    pub async fn authenticate(
        &self,
        client: &mut FileTransferServiceClient<Channel>,
    ) -> Result<()> {
        info!("Authenticating with remote node");

        // Create challenge data
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let challenge_data = format!("{}:{}", self.identity.address(), timestamp);

        // Sign the challenge
        let signature = CertificateManager::sign_data(
            self.identity
                .private_key_pem
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Private key not available"))?,
            challenge_data.as_bytes(),
        )?;

        let auth_request = AuthRequest {
            certificate: self.identity.certificate().to_string(),
            signature,
            node_address: self.identity.address().to_string(),
            timestamp,
        };

        let response = client.authenticate(auth_request).await?;
        let auth_response = response.into_inner();

        if !auth_response.authenticated {
            anyhow::bail!("Authentication failed: {}", auth_response.message);
        }

        info!("Authentication successful");

        Ok(())
    }

    /// Upload a file to a remote node
    pub async fn upload_file<P: AsRef<Path>>(
        &self,
        client: &mut FileTransferServiceClient<Channel>,
        file_path: P,
        mime_type: Option<String>,
    ) -> Result<String> {
        let file_path = file_path.as_ref();
        let filename = file_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?
            .to_string_lossy()
            .to_string();

        info!("Uploading file: {}", filename);

        // Get file metadata
        let metadata = tokio::fs::metadata(file_path).await?;
        let file_size = metadata.len();

        // Calculate checksum
        let checksum = super::calculate_checksum(file_path).await?;

        // Read file chunks
        let chunks = super::read_file_chunks(file_path, self.chunk_size).await?;
        let total_chunks = chunks.len() as u64;

        // Clone values needed for the stream
        let source_ip = self.identity.address().ip().to_string();

        // Create stream
        let stream = async_stream::stream! {
            // First chunk with metadata
            if let Some(first_chunk) = chunks.first() {
                yield FileChunk {
                    metadata: Some(FileMetadata {
                        filename: filename.clone(),
                        file_size,
                        mime_type: mime_type.clone().unwrap_or_else(|| "application/octet-stream".to_string()),
                        source_ip: source_ip.clone(),
                        timestamp: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as i64,
                        checksum: checksum.clone(),
                    }),
                    data: first_chunk.clone(),
                    chunk_number: 0,
                    total_chunks: Some(total_chunks),
                };
            }

            // Remaining chunks
            for (i, chunk) in chunks.iter().skip(1).enumerate() {
                yield FileChunk {
                    metadata: None,
                    data: chunk.clone(),
                    chunk_number: (i + 1) as u64,
                    total_chunks: None,
                };
            }
        };

        // Add certificate to metadata
        let mut request = Request::new(stream);
        let cert_value = MetadataValue::try_from(self.identity.certificate())?;
        request.metadata_mut().insert("x-certificate", cert_value);

        // Send the request
        let response = client.upload_file(request).await?;
        let upload_response = response.into_inner();

        if !upload_response.success {
            anyhow::bail!("Upload failed: {}", upload_response.message);
        }

        info!(
            "Upload successful: {} bytes (ID: {})",
            upload_response.bytes_received, upload_response.file_id
        );

        Ok(upload_response.file_id)
    }

    /// Download a file from a remote node
    pub async fn download_file(
        &self,
        client: &mut FileTransferServiceClient<Channel>,
        file_id: &str,
        output_path: &Path,
    ) -> Result<()> {
        info!("Downloading file: {}", file_id);

        let download_request = DownloadRequest {
            file_id: file_id.to_string(),
            start_chunk: None,
        };

        // Add certificate to metadata
        let mut request = Request::new(download_request);
        let cert_value = MetadataValue::try_from(self.identity.certificate())?;
        request.metadata_mut().insert("x-certificate", cert_value);

        // Get the stream
        let mut stream = client.download_file(request).await?.into_inner();

        // Create output file
        let mut output_file = File::create(output_path).await?;
        let mut bytes_received = 0u64;
        let mut metadata: Option<FileMetadata> = None;

        // Receive chunks
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;

            // Store metadata from first chunk
            if metadata.is_none() {
                metadata = chunk.metadata;
            }

            // Write chunk data
            if !chunk.data.is_empty() {
                output_file.write_all(&chunk.data).await?;
                bytes_received += chunk.data.len() as u64;
                debug!("Received chunk {} ({} bytes)", chunk.chunk_number, chunk.data.len());
            }
        }

        output_file.flush().await?;
        output_file.sync_all().await?;

        info!("Download complete: {} bytes", bytes_received);

        // Verify checksum if available
        if let Some(meta) = metadata {
            let downloaded_checksum = super::calculate_checksum(output_path).await?;
            if downloaded_checksum != meta.checksum {
                anyhow::bail!(
                    "Checksum mismatch: expected {}, got {}",
                    meta.checksum,
                    downloaded_checksum
                );
            }
            info!("Checksum verified");
        }

        Ok(())
    }

    /// List files on a remote node
    pub async fn list_files(
        &self,
        client: &mut FileTransferServiceClient<Channel>,
        source_ip: Option<String>,
        page: u32,
        page_size: u32,
    ) -> Result<Vec<crate::grpc::file_transfer::FileInfo>> {
        let list_request = ListFilesRequest {
            source_ip,
            page,
            page_size,
        };

        // Add certificate to metadata
        let mut request = Request::new(list_request);
        let cert_value = MetadataValue::try_from(self.identity.certificate())?;
        request.metadata_mut().insert("x-certificate", cert_value);

        let response = client.list_files(request).await?;
        let list_response = response.into_inner();

        info!("Found {} files", list_response.files.len());

        Ok(list_response.files)
    }

    /// Ping a remote node
    pub async fn ping(
        &self,
        client: &mut FileTransferServiceClient<Channel>,
    ) -> Result<String> {
        let ping_request = PingRequest {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        };

        let response = client.ping(ping_request).await?;
        let ping_response = response.into_inner();

        Ok(ping_response.node_id)
    }

    /// Upload file to multiple servers concurrently
    pub async fn upload_to_multiple(
        &self,
        server_addresses: &[String],
        file_path: &Path,
        mime_type: Option<String>,
    ) -> Result<Vec<Result<String>>> {
        info!("Uploading to {} servers concurrently", server_addresses.len());

        let mut tasks = Vec::new();

        for address in server_addresses {
            let address = address.clone();
            let file_path = file_path.to_path_buf();
            let mime_type = mime_type.clone();
            let client = self.clone();

            let task = tokio::spawn(async move {
                let mut grpc_client = client.connect(&address).await?;
                client.authenticate(&mut grpc_client).await?;
                client.upload_file(&mut grpc_client, &file_path, mime_type).await
            });

            tasks.push(task);
        }

        // Wait for all uploads to complete
        let mut results = Vec::new();
        for task in tasks {
            let result = task.await.map_err(|e| anyhow::anyhow!("Task failed: {}", e))?;
            results.push(result);
        }

        info!("All uploads completed");

        Ok(results)
    }
}

impl Clone for FileTransferClient {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity.clone(),
            chunk_size: self.chunk_size,
        }
    }
}
