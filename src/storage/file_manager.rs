use anyhow::{Context, Result};
use ring::digest;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, info};

use super::StorageConfig;

/// File metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub filename: String,
    pub file_size: u64,
    pub mime_type: String,
    pub source_ip: String,
    pub timestamp: i64,
    pub checksum: String,
}

/// Stored file information
#[derive(Debug, Clone)]
pub struct StoredFile {
    pub file_id: String,
    pub metadata: FileMetadata,
    pub storage_path: PathBuf,
}

/// File manager for handling file storage and retrieval
pub struct FileManager {
    config: StorageConfig,
}

impl FileManager {
    /// Create a new file manager
    pub fn new(config: StorageConfig) -> Result<Self> {
        config.ensure_directories()?;
        Ok(Self { config })
    }

    /// Generate a unique file ID
    fn generate_file_id(filename: &str, source_ip: &IpAddr, timestamp: i64) -> String {
        let data = format!("{}:{}:{}", filename, source_ip, timestamp);
        let hash = digest::digest(&digest::SHA256, data.as_bytes());
        hex::encode(&hash.as_ref()[..16])
    }

    /// Get storage path for a file
    fn get_storage_path(&self, source_ip: &IpAddr, file_id: &str, filename: &str) -> PathBuf {
        let ip_dir = self.config.get_ip_dir(source_ip);
        ip_dir.join(format!("{}_{}", file_id, filename))
    }

    /// Store file metadata
    async fn store_metadata(&self, source_ip: &IpAddr, file_id: &str, metadata: &FileMetadata) -> Result<()> {
        let ip_dir = self.config.get_ip_dir(source_ip);
        fs::create_dir_all(&ip_dir).await?;

        let metadata_path = ip_dir.join(format!("{}.meta.json", file_id));
        let metadata_json = serde_json::to_string_pretty(metadata)?;

        let mut file = File::create(&metadata_path).await?;
        file.write_all(metadata_json.as_bytes()).await?;

        Ok(())
    }

    /// Load file metadata
    async fn load_metadata(&self, source_ip: &IpAddr, file_id: &str) -> Result<FileMetadata> {
        let ip_dir = self.config.get_ip_dir(source_ip);
        let metadata_path = ip_dir.join(format!("{}.meta.json", file_id));

        let metadata_json = fs::read_to_string(&metadata_path).await?;
        let metadata: FileMetadata = serde_json::from_str(&metadata_json)?;

        Ok(metadata)
    }

    /// Start writing a file (returns a FileWriter)
    pub async fn start_write(
        &self,
        filename: String,
        source_ip: IpAddr,
        file_size: u64,
        mime_type: String,
    ) -> Result<FileWriter> {
        // Check file size limit
        if self.config.max_file_size > 0 && file_size > self.config.max_file_size {
            anyhow::bail!(
                "File size {} exceeds maximum allowed size {}",
                file_size,
                self.config.max_file_size
            );
        }

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let file_id = Self::generate_file_id(&filename, &source_ip, timestamp);
        let storage_path = self.get_storage_path(&source_ip, &file_id, &filename);

        // Ensure directory exists
        let ip_dir = self.config.get_ip_dir(&source_ip);
        fs::create_dir_all(&ip_dir).await?;

        // Create the file
        let file = File::create(&storage_path)
            .await
            .context("Failed to create file")?;

        info!(
            "Started writing file: {} (ID: {}) from {}",
            filename, file_id, source_ip
        );

        Ok(FileWriter {
            file_id: file_id.clone(),
            filename,
            source_ip,
            file_size,
            mime_type,
            timestamp,
            storage_path,
            file,
            bytes_written: 0,
            hasher: ring::digest::Context::new(&ring::digest::SHA256),
        })
    }

    /// Start reading a file (returns a FileReader)
    pub async fn start_read(&self, file_id: &str, source_ip: &IpAddr) -> Result<FileReader> {
        let metadata = self.load_metadata(source_ip, file_id).await?;
        let storage_path = self.get_storage_path(source_ip, file_id, &metadata.filename);

        let file = File::open(&storage_path)
            .await
            .context("Failed to open file")?;

        info!("Started reading file: {} (ID: {})", metadata.filename, file_id);

        Ok(FileReader {
            file_id: file_id.to_string(),
            metadata,
            file,
            bytes_read: 0,
            chunk_size: self.config.chunk_size,
        })
    }

    /// List files for a specific IP address
    pub async fn list_files(&self, source_ip: &IpAddr) -> Result<Vec<StoredFile>> {
        let ip_dir = self.config.get_ip_dir(source_ip);

        if !ip_dir.exists() {
            return Ok(Vec::new());
        }

        let mut files = Vec::new();
        let mut entries = fs::read_dir(&ip_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if let Some(filename) = path.file_name() {
                let filename_str = filename.to_string_lossy();

                // Look for metadata files
                if filename_str.ends_with(".meta.json") {
                    let file_id = filename_str.trim_end_matches(".meta.json");

                    if let Ok(metadata) = self.load_metadata(source_ip, file_id).await {
                        let storage_path = self.get_storage_path(source_ip, file_id, &metadata.filename);

                        files.push(StoredFile {
                            file_id: file_id.to_string(),
                            metadata,
                            storage_path,
                        });
                    }
                }
            }
        }

        Ok(files)
    }

    /// List all files across all IPs
    pub async fn list_all_files(&self) -> Result<Vec<StoredFile>> {
        let mut all_files = Vec::new();

        if !self.config.root_dir.exists() {
            return Ok(all_files);
        }

        let mut entries = fs::read_dir(&self.config.root_dir).await?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            if path.is_dir() {
                if let Some(ip_str) = path.file_name() {
                    if let Ok(ip_addr) = ip_str.to_string_lossy().parse::<IpAddr>() {
                        let mut ip_files = self.list_files(&ip_addr).await?;
                        all_files.append(&mut ip_files);
                    }
                }
            }
        }

        Ok(all_files)
    }

    /// Delete a file
    #[allow(dead_code)]
    pub async fn delete_file(&self, file_id: &str, source_ip: &IpAddr) -> Result<()> {
        let metadata = self.load_metadata(source_ip, file_id).await?;
        let storage_path = self.get_storage_path(source_ip, file_id, &metadata.filename);
        let ip_dir = self.config.get_ip_dir(source_ip);
        let metadata_path = ip_dir.join(format!("{}.meta.json", file_id));

        // Delete the file and metadata
        if storage_path.exists() {
            fs::remove_file(&storage_path).await?;
        }

        if metadata_path.exists() {
            fs::remove_file(&metadata_path).await?;
        }

        info!("Deleted file: {} (ID: {})", metadata.filename, file_id);

        Ok(())
    }

    /// Get storage statistics
    #[allow(dead_code)]
    pub async fn get_stats(&self) -> Result<StorageStats> {
        let mut total_files = 0;
        let mut total_size = 0u64;

        let files = self.list_all_files().await?;

        for file in files {
            total_files += 1;
            total_size += file.metadata.file_size;
        }

        Ok(StorageStats {
            total_files,
            total_size,
        })
    }
}

/// File writer for streaming writes
#[allow(dead_code)]
pub struct FileWriter {
    pub file_id: String,
    filename: String,
    source_ip: IpAddr,
    file_size: u64,
    mime_type: String,
    timestamp: i64,
    storage_path: PathBuf,
    file: File,
    bytes_written: u64,
    hasher: ring::digest::Context,
}

#[allow(dead_code)]
impl FileWriter {
    /// Write a chunk of data
    pub async fn write_chunk(&mut self, data: &[u8]) -> Result<usize> {
        self.file.write_all(data).await?;
        self.bytes_written += data.len() as u64;
        self.hasher.update(data);

        debug!("Wrote {} bytes (total: {})", data.len(), self.bytes_written);

        Ok(data.len())
    }

    /// Finalize the write and return metadata
    pub async fn finalize(mut self, storage_manager: &FileManager) -> Result<FileMetadata> {
        self.file.flush().await?;
        self.file.sync_all().await?;

        let checksum = hex::encode(self.hasher.finish().as_ref());

        let metadata = FileMetadata {
            filename: self.filename,
            file_size: self.bytes_written,
            mime_type: self.mime_type,
            source_ip: self.source_ip.to_string(),
            timestamp: self.timestamp,
            checksum,
        };

        // Store metadata
        storage_manager
            .store_metadata(&self.source_ip, &self.file_id, &metadata)
            .await?;

        info!(
            "Finalized file: {} ({} bytes, checksum: {})",
            metadata.filename, metadata.file_size, metadata.checksum
        );

        Ok(metadata)
    }

    /// Get current progress
    pub fn progress(&self) -> (u64, u64) {
        (self.bytes_written, self.file_size)
    }
}

/// File reader for streaming reads
#[allow(dead_code)]
pub struct FileReader {
    pub file_id: String,
    pub metadata: FileMetadata,
    file: File,
    bytes_read: u64,
    chunk_size: usize,
}

#[allow(dead_code)]
impl FileReader {
    /// Read the next chunk
    pub async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>> {
        let mut buffer = vec![0u8; self.chunk_size];
        let n = self.file.read(&mut buffer).await?;

        if n == 0 {
            return Ok(None);
        }

        buffer.truncate(n);
        self.bytes_read += n as u64;

        debug!("Read {} bytes (total: {})", n, self.bytes_read);

        Ok(Some(buffer))
    }

    /// Get current progress
    pub fn progress(&self) -> (u64, u64) {
        (self.bytes_read, self.metadata.file_size)
    }

    /// Check if reading is complete
    pub fn is_complete(&self) -> bool {
        self.bytes_read >= self.metadata.file_size
    }
}

/// Storage statistics
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_files: usize,
    pub total_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_write_read() {
        let config = StorageConfig {
            root_dir: PathBuf::from("./test_storage"),
            ..Default::default()
        };

        let manager = FileManager::new(config).unwrap();
        let source_ip: IpAddr = "192.168.1.100".parse().unwrap();

        // Write a file
        let mut writer = manager
            .start_write("test.txt".to_string(), source_ip, 100, "text/plain".to_string())
            .await
            .unwrap();

        let file_id = writer.file_id.clone();
        writer.write_chunk(b"Hello, World!").await.unwrap();
        let metadata = writer.finalize(&manager).await.unwrap();

        assert_eq!(metadata.file_size, 13);

        // Read the file back
        let mut reader = manager.start_read(&file_id, &source_ip).await.unwrap();
        let chunk = reader.read_chunk().await.unwrap();

        assert!(chunk.is_some());
        assert_eq!(chunk.unwrap(), b"Hello, World!");

        // Cleanup
        manager.delete_file(&file_id, &source_ip).await.unwrap();
        std::fs::remove_dir_all("./test_storage").ok();
    }
}
