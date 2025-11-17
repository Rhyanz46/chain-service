use anyhow::{Context, Result};
use std::path::Path;
use std::time::Duration;
use tokio::fs;
use tokio::time::interval;
use tracing::{debug, error, info, warn};
use walkdir::{DirEntry, WalkDir};

use crate::config::AutoUploadConfig;
use crate::network::FileTransferClient;
use crate::pki::NodeIdentity;

/// File watcher that scans directory for new files
pub struct FileWatcher {
    config: AutoUploadConfig,
    client: FileTransferClient,
    identity: NodeIdentity,
}

impl FileWatcher {
    pub fn new(config: AutoUploadConfig, client: FileTransferClient, identity: NodeIdentity) -> Self {
        Self {
            config,
            client,
            identity,
        }
    }

    /// Start the file watcher with periodic scanning
    pub async fn start(&self) -> Result<()> {
        info!("🔄 Starting auto upload file watcher");
        info!("📁 Watch folder: {}", self.config.watch_folder.display());
        info!("⏰ Scan interval: {} seconds", self.config.scan_interval_seconds);
        info!("🎯 Destination servers: {:?}", self.config.destination_servers);

        // Log current user context
        let current_user = std::env::var("USER").unwrap_or_else(|_| "unknown".to_string());
        info!("👤 Running as user: {}", current_user);

        // Log folder path details
        info!("🔍 Checking watch folder path: {}", self.config.watch_folder.display());
        info!("🔍 Path is absolute: {}", self.config.watch_folder.is_absolute());

        // Check parent directory
        if let Some(parent) = self.config.watch_folder.parent() {
            info!("📂 Parent directory: {}", parent.display());
            info!("📂 Parent exists: {}", parent.exists());
            if parent.exists() {
                match std::fs::metadata(parent) {
                    Ok(metadata) => {
                        info!("📂 Parent permissions: {:?}", metadata.permissions());
                    }
                    Err(e) => {
                        warn!("⚠️  Cannot read parent metadata: {}", e);
                    }
                }
            }
        }

        // Ensure watch folder exists
        info!("🔍 Checking if watch folder exists: {}", self.config.watch_folder.exists());

        if !self.config.watch_folder.exists() {
            info!("📁 Watch folder doesn't exist, attempting to create: {}", self.config.watch_folder.display());

            match fs::create_dir_all(&self.config.watch_folder).await {
                Ok(_) => {
                    info!("✅ Successfully created watch folder: {}", self.config.watch_folder.display());
                }
                Err(e) => {
                    error!("❌ Failed to create watch folder: {}", e);
                    error!("❌ Error kind: {:?}", e.kind());
                    error!("❌ Path: {}", self.config.watch_folder.display());
                    return Err(anyhow::anyhow!(
                        "Failed to create watch folder: {} - Error: {} - Run: sudo uploader set-access-watch-folder {}",
                        self.config.watch_folder.display(),
                        e,
                        self.config.watch_folder.display()
                    ));
                }
            }
        } else {
            info!("✅ Watch folder exists: {}", self.config.watch_folder.display());

            // Log folder metadata
            match std::fs::metadata(&self.config.watch_folder) {
                Ok(metadata) => {
                    info!("📊 Folder permissions: {:?}", metadata.permissions());
                    info!("📊 Is directory: {}", metadata.is_dir());
                    info!("📊 Is readonly: {}", metadata.permissions().readonly());
                }
                Err(e) => {
                    error!("❌ Cannot read folder metadata: {}", e);
                }
            }

            // Test if we can access the folder
            info!("🔍 Testing folder read access...");
            match fs::read_dir(&self.config.watch_folder).await {
                Ok(_) => {
                    info!("✅ Watch folder is accessible for reading");
                }
                Err(e) => {
                    error!("❌ Watch folder exists but cannot be accessed: {} - Error: {}",
                           self.config.watch_folder.display(), e);
                    error!("❌ Error kind: {:?}", e.kind());
                    return Err(anyhow::anyhow!(
                        "Watch folder exists but permission denied: {} - Error: {} - Run: sudo uploader set-access-watch-folder {}",
                        self.config.watch_folder.display(),
                        e,
                        self.config.watch_folder.display()
                    ));
                }
            }
        }

        let mut interval_timer = interval(Duration::from_secs(self.config.scan_interval_seconds));
        interval_timer.tick().await; // Skip first immediate tick

        loop {
            tokio::select! {
                _ = interval_timer.tick() => {
                    if let Err(e) = self.scan_and_upload().await {
                        error!("❌ Auto upload scan failed: {}", e);
                    }
                }
                // Handle graceful shutdown here if needed
            }
        }
    }

    /// Scan directory for new files and upload them
    async fn scan_and_upload(&self) -> Result<()> {
        debug!("🔍 Scanning folder for new files...");

        let mut new_files_found = false;

        for entry in WalkDir::new(&self.config.watch_folder)
            .max_depth(1)
            .into_iter()
            .filter_entry(|e| !is_hidden(e))
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_file() && self.is_new_file(&entry.path()).await? {
                new_files_found = true;
                info!("📄 Found new file: {}", entry.path().display());

                if let Err(e) = self.upload_file(entry.path()).await {
                    error!("❌ Failed to upload {}: {}", entry.path().display(), e);
                } else {
                    info!("✅ Successfully uploaded: {}", entry.path().display());
                    if let Err(e) = self.rename_uploaded_file(entry.path()).await {
                        error!("❌ Failed to rename uploaded file: {}", e);
                    }
                }
            }
        }

        if !new_files_found {
            debug!("✅ No new files found");
        }

        Ok(())
    }

    /// Check if file should be uploaded (not already uploaded and matches criteria)
    async fn is_new_file(&self, file_path: &Path) -> Result<bool> {
        let file_name = file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Skip files that already have uploaded suffix (before extension)
        let file_stem = file_path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        if file_stem.ends_with(&self.config.upload_suffix) {
            debug!("⏭️ Skipping already uploaded file: {}", file_path.display());
            return Ok(false);
        }

        // Check file extensions filter
        if !self.config.file_extensions.is_empty() {
            if let Some(extension) = file_path.extension().and_then(|e| e.to_str()) {
                let extension_with_dot = format!(".{}", extension);
                if !self.config.file_extensions.contains(&extension_with_dot) {
                    debug!("⏭️ Skipping file with extension {}: {}", extension, file_path.display());
                    return Ok(false);
                }
            } else {
                debug!("⏭️ Skipping file without extension: {}", file_path.display());
                return Ok(false);
            }
        }

        // Check file size
        let metadata = fs::metadata(file_path).await
            .context("Failed to get file metadata")?;
        let file_size = metadata.len();

        if self.config.max_file_size > 0 && file_size > self.config.max_file_size {
            warn!("⏭️ Skipping large file: {} ({} bytes > {} bytes limit)",
                  file_path.display(), file_size, self.config.max_file_size);
            return Ok(false);
        }

        Ok(true)
    }

    /// Upload file to all destination servers
    async fn upload_file(&self, file_path: &Path) -> Result<()> {
        if self.config.destination_servers.is_empty() {
            warn!("⚠️ No destination servers configured");
            return Ok(());
        }

        info!("📤 Uploading {} to {} servers...",
              file_path.display(),
              self.config.destination_servers.len());

        // Normalize server addresses - add default port :50051 if not specified
        let normalized_servers: Vec<String> = self.config.destination_servers
            .iter()
            .map(|server| {
                if server.contains(':') {
                    server.clone()
                } else {
                    format!("{}:50051", server)
                }
            })
            .collect();

        let results = self.client.upload_to_multiple(
            &normalized_servers,
            file_path,
            None, // Let server detect MIME type
        ).await?;

        // Check results
        let mut success_count = 0;
        let mut failure_count = 0;

        for (i, result) in results.iter().enumerate() {
            match result {
                Ok(file_id) => {
                    success_count += 1;
                    info!("✅ Upload to {} successful (ID: {})",
                          normalized_servers[i], file_id);
                }
                Err(e) => {
                    failure_count += 1;
                    error!("❌ Upload to {} failed: {}",
                           normalized_servers[i], e);
                }
            }
        }

        if success_count > 0 {
            info!("🎯 Upload summary: {} successful, {} failed", success_count, failure_count);
            Ok(())
        } else {
            anyhow::bail!("All uploads failed for {}", file_path.display());
        }
    }

    /// Rename file after successful upload
    async fn rename_uploaded_file(&self, file_path: &Path) -> Result<()> {
        if !self.config.rename_after_upload {
            debug!("⏭️ File renaming disabled, skipping rename");
            return Ok(());
        }

        let file_stem = file_path.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| anyhow::anyhow!("Invalid file name"))?;

        let extension = file_path.extension()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        let new_name = if extension.is_empty() {
            format!("{}{}", file_stem, self.config.upload_suffix)
        } else {
            format!("{}{}.{}", file_stem, self.config.upload_suffix, extension)
        };

        let new_path = file_path.parent()
            .unwrap_or_else(|| Path::new("."))
            .join(new_name);

        fs::rename(file_path, &new_path).await
            .context("Failed to rename uploaded file")?;

        debug!("🏷️ Renamed to: {}", new_path.display());
        Ok(())
    }
}

/// Check if directory entry is hidden
fn is_hidden(entry: &DirEntry) -> bool {
    entry.file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}