pub mod file_manager;

pub use file_manager::{FileManager, FileMetadata, StoredFile};

use anyhow::Result;
use std::path::PathBuf;
use std::net::IpAddr;

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Root directory for file storage
    pub root_dir: PathBuf,

    /// Maximum file size in bytes (0 = unlimited)
    pub max_file_size: u64,

    /// Chunk size for streaming (default: 1MB)
    pub chunk_size: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from("./storage"),
            max_file_size: 0, // unlimited
            chunk_size: 1024 * 1024, // 1MB
        }
    }
}

impl StorageConfig {
    /// Get the directory path for a specific IP address
    pub fn get_ip_dir(&self, ip_addr: &IpAddr) -> PathBuf {
        self.root_dir.join(ip_addr.to_string())
    }

    /// Create all necessary directories
    pub fn ensure_directories(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root_dir)?;
        Ok(())
    }
}
