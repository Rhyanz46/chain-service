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
}

impl Default for Config {
    fn default() -> Self {
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
