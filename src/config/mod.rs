use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Node configuration
    pub node: NodeConfig,

    /// Network configuration
    pub network: NetworkConfig,

    /// Storage configuration
    pub storage: StorageConfig,

    /// Security configuration
    pub security: SecurityConfig,

    /// Network ID management configuration
    pub network_ids: NetworkIdConfig,

    /// Auto upload configuration
    #[serde(default)]
    pub auto_upload: AutoUploadConfig,
}

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node name
    pub name: String,

    /// Node listen address for gRPC
    pub listen_address: SocketAddr,

    /// Certificate file path
    pub certificate_path: PathBuf,

    /// Private key file path
    pub private_key_path: PathBuf,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// P2P listen port for distributed registry
    pub p2p_port: u16,

    /// Bootstrap nodes (other nodes to connect to initially)
    pub bootstrap_nodes: Vec<String>,

    /// Heartbeat interval in seconds
    pub heartbeat_interval: u64,

    /// Node timeout in seconds (consider node stale after this)
    pub node_timeout: u64,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Root directory for file storage
    pub root_dir: PathBuf,

    /// Maximum file size in bytes (0 = unlimited)
    pub max_file_size: u64,

    /// Chunk size for streaming in bytes
    pub chunk_size: usize,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Allow self-signed certificates
    pub allow_self_signed: bool,

    /// Certificate validity period in days
    pub cert_validity_days: u32,

    /// Require mutual TLS
    pub require_mtls: bool,

    /// Network secret for node authorization (optional, but HIGHLY recommended for production)
    /// If set, nodes must provide this secret to join the network
    #[serde(default)]
    pub network_secret: Option<String>,
}

/// Network ID management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIdConfig {
    /// Enable network ID management (if false, use auto-generated IDs)
    pub enabled: bool,

    /// Path to network IDs configuration file
    pub ids_config_path: PathBuf,

    /// Path to network state database
    pub state_db_path: PathBuf,

    /// Network ID reservation timeout in seconds
    #[serde(default = "default_reservation_timeout")]
    pub reservation_timeout: u64,

    /// Offline threshold in seconds before considering node stale (default: 24 hours)
    #[serde(default = "default_offline_threshold")]
    pub offline_threshold: u64,

    /// Cleanup interval in seconds (how often to check for stale nodes)
    #[serde(default = "default_cleanup_interval")]
    pub cleanup_interval: u64,

    /// Enable auto-recovery for empty networks
    #[serde(default = "default_auto_recovery")]
    pub auto_recovery: bool,

    /// Maximum nodes per network type
    #[serde(default)]
    pub max_nodes_per_network: std::collections::HashMap<String, u32>,
}

/// Auto upload configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoUploadConfig {
    /// Enable auto upload functionality
    #[serde(default)]
    pub enabled: bool,

    /// Scan interval in seconds (how often to check for new files)
    #[serde(default = "default_scan_interval")]
    pub scan_interval_seconds: u64,

    /// Directory to watch for new files
    #[serde(default)]
    pub watch_folder: PathBuf,

    /// Destination servers for auto upload
    #[serde(default)]
    pub destination_servers: Vec<String>,

    /// File extensions to monitor (empty = all files)
    #[serde(default)]
    pub file_extensions: Vec<String>,

    /// Maximum file size in bytes for auto upload (0 = unlimited)
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,

    /// Delete or rename files after successful upload
    #[serde(default = "default_rename_after_upload")]
    pub rename_after_upload: bool,

    /// Custom suffix for uploaded files (default: "_uploaded")
    #[serde(default = "default_upload_suffix")]
    pub upload_suffix: String,
}

impl Default for AutoUploadConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default
            scan_interval_seconds: 60, // 1 minute
            watch_folder: PathBuf::from("./uploads"),
            destination_servers: Vec::new(),
            file_extensions: Vec::new(), // All files
            max_file_size: 1073741824, // 1GB
            rename_after_upload: true,
            upload_suffix: "_uploaded".to_string(),
        }
    }
}

// Default values for configuration options
fn default_reservation_timeout() -> u64 { 300 } // 5 minutes
fn default_offline_threshold() -> u64 { 86400 } // 24 hours
fn default_cleanup_interval() -> u64 { 3600 } // 1 hour
fn default_auto_recovery() -> bool { true }

// Default values for auto upload configuration
fn default_scan_interval() -> u64 { 60 } // 1 minute
fn default_max_file_size() -> u64 { 1073741824 } // 1GB
fn default_rename_after_upload() -> bool { true }
fn default_upload_suffix() -> String { "_uploaded".to_string() }

impl Default for Config {
    fn default() -> Self {
        let mut max_nodes = std::collections::HashMap::new();
        max_nodes.insert("MainNet".to_string(), 999);
        max_nodes.insert("TestNet".to_string(), 99);
        max_nodes.insert("DevNet".to_string(), 49);
        max_nodes.insert("CustomNet".to_string(), 99);

        Self {
            node: NodeConfig {
                name: "node-1".to_string(),
                listen_address: "0.0.0.0:50051".parse().unwrap(),
                certificate_path: PathBuf::from("./certs/node.crt"),
                private_key_path: PathBuf::from("./certs/node.key"),
            },
            network: NetworkConfig {
                p2p_port: 9000,
                bootstrap_nodes: Vec::new(),
                heartbeat_interval: 30,
                node_timeout: 300,
            },
            storage: StorageConfig {
                root_dir: PathBuf::from("./storage"),
                max_file_size: 0, // unlimited
                chunk_size: 1024 * 1024, // 1MB
            },
            security: SecurityConfig {
                allow_self_signed: true,
                cert_validity_days: 365,
                require_mtls: true,
                network_secret: None, // No secret by default (INSECURE - set in production!)
            },
            network_ids: NetworkIdConfig {
                enabled: false, // Disabled by default for backward compatibility
                ids_config_path: PathBuf::from("./config/network_ids.toml"),
                state_db_path: PathBuf::from("./data/network_state.json"),
                reservation_timeout: 300, // 5 minutes
                offline_threshold: 86400, // 24 hours
                cleanup_interval: 3600, // 1 hour
                auto_recovery: true,
                max_nodes_per_network: max_nodes,
            },
            auto_upload: AutoUploadConfig {
                enabled: false, // Disabled by default
                scan_interval_seconds: 60, // 1 minute
                watch_folder: PathBuf::from("./uploads"),
                destination_servers: Vec::new(),
                file_extensions: Vec::new(), // All files
                max_file_size: 1073741824, // 1GB
                rename_after_upload: true,
                upload_suffix: "_uploaded".to_string(),
            },
        }
    }
}

impl Config {
    /// Load configuration from a file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .context("Failed to read config file")?;

        let config: Config = toml::from_str(&content)
            .context("Failed to parse config file")?;

        Ok(config)
    }

    /// Save configuration to a file
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .context("Failed to serialize config")?;

        fs::write(path.as_ref(), content)
            .context("Failed to write config file")?;

        Ok(())
    }

    /// Create a default config file
    pub fn create_default<P: AsRef<Path>>(path: P) -> Result<()> {
        let config = Self::default();
        config.to_file(path)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate listen address
        if self.node.listen_address.port() == 0 {
            anyhow::bail!("Invalid listen address port");
        }

        // Validate storage path
        if self.storage.root_dir.to_string_lossy().is_empty() {
            anyhow::bail!("Storage root directory cannot be empty");
        }

        // Validate chunk size
        if self.storage.chunk_size == 0 {
            anyhow::bail!("Chunk size must be greater than 0");
        }

        Ok(())
    }

    /// Ensure all necessary directories exist
    pub fn ensure_directories(&self) -> Result<()> {
        // Create storage directory
        fs::create_dir_all(&self.storage.root_dir)
            .context("Failed to create storage directory")?;

        // Create certificate directory
        if let Some(cert_dir) = self.node.certificate_path.parent() {
            fs::create_dir_all(cert_dir)
                .context("Failed to create certificate directory")?;
        }

        // Create network IDs config directory
        if let Some(ids_dir) = self.network_ids.ids_config_path.parent() {
            fs::create_dir_all(ids_dir)
                .context("Failed to create network IDs config directory")?;
        }

        // Create network state database directory
        if let Some(db_dir) = self.network_ids.state_db_path.parent() {
            fs::create_dir_all(db_dir)
                .context("Failed to create network state database directory")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        let parsed: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(config.node.name, parsed.node.name);
    }
}
