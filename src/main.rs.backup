mod config;
mod grpc;
mod network;
mod pki;
mod registry;
mod storage;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::time::{interval, Duration};
use tracing::{error, info};
use tracing_subscriber;

use config::Config;
use network::{FileTransferClient, FileTransferServer};
use pki::{CertificateManager, CertificateValidator, NodeIdentity};
use registry::{DistributedRegistry, NodeRegistry};
use storage::{FileManager, StorageConfig};

/// Discover config file with priority order
fn discover_config(cli_path: Option<PathBuf>) -> PathBuf {
    // Priority 1: CLI specified path
    if let Some(path) = cli_path {
        return path;
    }

    // Priority 2: Current directory config.toml
    let local_config = PathBuf::from("config.toml");
    if local_config.exists() {
        return local_config;
    }

    // Priority 3: System config /etc/uploader/config.toml
    let system_config = PathBuf::from("/etc/uploader/config.toml");
    if system_config.exists() {
        return system_config;
    }

    // Priority 4: Fallback to creating config.toml in current directory
    // This allows users to run without system-wide installation
    local_config
}

#[derive(Parser)]
#[command(name = "uploader")]
#[command(about = "Distributed file transfer system with blockchain-based authentication")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Config file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new certificate for this node
    GenCert {
        /// Node name
        #[arg(short, long)]
        name: String,

        /// Node address (IP:PORT)
        #[arg(short, long)]
        address: String,

        /// Output certificate file
        #[arg(short, long, default_value = "node.crt")]
        cert_out: PathBuf,

        /// Output private key file
        #[arg(short, long, default_value = "node.key")]
        key_out: PathBuf,
    },

    /// Initialize default configuration
    InitConfig {
        /// Output config file
        #[arg(short, long, default_value = "config.toml")]
        output: PathBuf,
    },

    /// Start the server
    Server,

    /// Upload a file to remote server(s)
    Upload {
        /// File to upload
        #[arg(short, long)]
        file: PathBuf,

        /// Remote server addresses (can specify multiple)
        #[arg(short, long)]
        servers: Vec<String>,

        /// MIME type (optional)
        #[arg(short, long)]
        mime_type: Option<String>,
    },

    /// Download a file from remote server
    Download {
        /// Server address
        #[arg(short, long)]
        server: String,

        /// File ID (format: source_ip/file_id)
        #[arg(short, long)]
        file_id: String,

        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },

    /// List files on remote server
    List {
        /// Server address
        #[arg(short, long)]
        server: String,

        /// Filter by source IP (optional)
        #[arg(long)]
        source_ip: Option<String>,

        /// Page number
        #[arg(long, default_value = "1")]
        page: u32,

        /// Page size
        #[arg(long, default_value = "10")]
        page_size: u32,
    },

    /// Ping a remote server
    Ping {
        /// Server address
        #[arg(short, long)]
        server: String,
    },

    /// List all connected nodes in the network
    ListNodes {
        /// Server address to query
        #[arg(short, long)]
        server: String,

        /// Include inactive/stale nodes
        #[arg(long)]
        include_stale: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    match cli.command {
        Commands::GenCert {
            name,
            address,
            cert_out,
            key_out,
        } => {
            generate_certificate(&name, &address, &cert_out, &key_out).await?;
        }

        Commands::InitConfig { output } => {
            Config::create_default(&output)?;
            info!("Created default configuration at {}", output.display());
        }

        Commands::Server => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)
                .context("Failed to load config. Run 'uploader init-config' first")?;

            run_server(config).await?;
        }

        Commands::Upload {
            file,
            servers,
            mime_type,
        } => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)?;
            upload_file(&config, &file, &servers, mime_type).await?;
        }

        Commands::Download {
            server,
            file_id,
            output,
        } => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)?;
            download_file(&config, &server, &file_id, &output).await?;
        }

        Commands::List {
            server,
            source_ip,
            page,
            page_size,
        } => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)?;
            list_files(&config, &server, source_ip, page, page_size).await?;
        }

        Commands::Ping { server } => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)?;
            ping_server(&config, &server).await?;
        }

        Commands::ListNodes {
            server,
            include_stale,
        } => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)?;
            list_nodes(&config, &server, include_stale).await?;
        }
    }

    Ok(())
}

async fn generate_certificate(
    name: &str,
    address: &str,
    cert_out: &PathBuf,
    key_out: &PathBuf,
) -> Result<()> {
    info!("Generating certificate for node '{}' at {}", name, address);

    let addr: SocketAddr = address.parse().context("Invalid address format")?;
    let cert = CertificateManager::generate_node_certificate(name, &addr)?;

    // Write certificate
    tokio::fs::write(cert_out, &cert.certificate_pem).await?;
    info!("Certificate written to {}", cert_out.display());

    // Write private key
    tokio::fs::write(key_out, &cert.private_key_pem).await?;
    info!("Private key written to {}", key_out.display());

    info!("Node ID: {}", cert.node_id);

    Ok(())
}

async fn run_server(config: Config) -> Result<()> {
    info!("Starting file transfer node: {}", config.node.name);

    // Validate config
    config.validate()?;
    config.ensure_directories()?;

    // Load or generate certificate
    let identity = load_or_generate_identity(&config).await?;

    info!("Node ID: {}", identity.node_id);
    info!("Node Address: {}", identity.address);

    // Initialize components
    let storage_config = StorageConfig {
        root_dir: config.storage.root_dir.clone(),
        max_file_size: config.storage.max_file_size,
        chunk_size: config.storage.chunk_size,
    };

    let file_manager = FileManager::new(storage_config)?;
    let certificate_validator = CertificateValidator::new(config.security.allow_self_signed);
    let node_registry = NodeRegistry::new(config.network.node_timeout as i64);

    // Add our own certificate to trusted list
    certificate_validator.add_trusted_certificate(&identity.certificate_pem)?;

    // Initialize distributed registry
    let (mut distributed_registry, mut event_receiver) = DistributedRegistry::new(
        node_registry.clone(),
        certificate_validator.clone(),
        identity.node_id.clone(),
    )?;

    distributed_registry.initialize(config.network.p2p_port).await?;

    // Start the gRPC server (with or without ID management)
    let server = if config.network_ids.enabled {
        info!("Starting server with ID management enabled");
        FileTransferServer::new_with_id_management(
            config.node.listen_address,
            file_manager,
            certificate_validator,
            node_registry.clone(),
            identity.clone(),
            config.security.clone(),
            config.network_ids.clone(),
        ).await?
    } else {
        info!("Starting server in legacy mode (ID management disabled)");
        FileTransferServer::new(
            config.node.listen_address,
            file_manager,
            certificate_validator,
            node_registry.clone(),
            identity.clone(),
            config.security.clone(),
        )
    };

    // Spawn server task
    let server_task = tokio::spawn(async move {
        if let Err(e) = server.start().await {
            error!("Server error: {}", e);
        }
    });

    // Spawn distributed registry task
    let registry_task = tokio::spawn(async move {
        if let Err(e) = distributed_registry.run().await {
            error!("Registry error: {}", e);
        }
    });

    // Spawn event handler task
    let event_task = tokio::spawn(async move {
        while let Some(event) = event_receiver.recv().await {
            match event {
                registry::RegistryEvent::NodeJoined(node) => {
                    info!("Node joined network: {} at {}", node.node_id, node.address);
                }
                registry::RegistryEvent::NodeLeft(node_id) => {
                    info!("Node left network: {}", node_id);
                }
                registry::RegistryEvent::NodeUpdated(node) => {
                    info!("Node updated: {} at {}", node.node_id, node.address);
                }
            }
        }
    });

    // Spawn heartbeat task
    let heartbeat_interval = config.network.heartbeat_interval;
    let heartbeat_task = tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(heartbeat_interval));
        loop {
            ticker.tick().await;
            // Heartbeat logic would go here
        }
    });

    info!("Server running on {}", config.node.listen_address);
    info!("P2P network running on port {}", config.network.p2p_port);

    // Wait for tasks
    tokio::select! {
        _ = server_task => {},
        _ = registry_task => {},
        _ = event_task => {},
        _ = heartbeat_task => {},
    }

    Ok(())
}

async fn upload_file(
    config: &Config,
    file_path: &PathBuf,
    servers: &[String],
    mime_type: Option<String>,
) -> Result<()> {
    info!("Uploading {} to {} servers", file_path.display(), servers.len());

    let identity = load_or_generate_identity(config).await?;
    let client = FileTransferClient::new(identity, config.storage.chunk_size);

    let results = client
        .upload_to_multiple(servers, file_path, mime_type)
        .await?;

    for (i, result) in results.iter().enumerate() {
        match result {
            Ok(file_id) => {
                info!("Upload to {} succeeded. File ID: {}", servers[i], file_id);
            }
            Err(e) => {
                error!("Upload to {} failed: {}", servers[i], e);
            }
        }
    }

    Ok(())
}

async fn download_file(
    config: &Config,
    server: &str,
    file_id: &str,
    output: &PathBuf,
) -> Result<()> {
    info!("Downloading {} from {}", file_id, server);

    let identity = load_or_generate_identity(config).await?;
    let client = FileTransferClient::new(identity, config.storage.chunk_size);

    let mut grpc_client = client.connect(server).await?;
    client.authenticate(&mut grpc_client).await?;
    client.download_file(&mut grpc_client, file_id, output).await?;

    info!("Downloaded to {}", output.display());

    Ok(())
}

async fn list_files(
    config: &Config,
    server: &str,
    source_ip: Option<String>,
    page: u32,
    page_size: u32,
) -> Result<()> {
    info!("Listing files on {}", server);

    let identity = load_or_generate_identity(config).await?;
    let client = FileTransferClient::new(identity, config.storage.chunk_size);

    let mut grpc_client = client.connect(server).await?;
    client.authenticate(&mut grpc_client).await?;

    let files = client
        .list_files(&mut grpc_client, source_ip, page, page_size)
        .await?;

    println!("\nFiles:");
    println!("{:<40} {:<30} {:<15} {:<20}", "File ID", "Filename", "Size", "Source IP");
    println!("{}", "-".repeat(105));

    for file_info in files {
        if let Some(meta) = file_info.metadata {
            println!(
                "{:<40} {:<30} {:<15} {:<20}",
                file_info.file_id,
                meta.filename,
                format_size(meta.file_size),
                meta.source_ip
            );
        }
    }

    Ok(())
}

async fn ping_server(config: &Config, server: &str) -> Result<()> {
    info!("Pinging {}", server);

    let identity = load_or_generate_identity(config).await?;
    let client = FileTransferClient::new(identity, config.storage.chunk_size);

    let mut grpc_client = client.connect(server).await?;
    let node_id = client.ping(&mut grpc_client).await?;

    info!("Pong from node: {}", node_id);

    Ok(())
}

async fn list_nodes(config: &Config, server: &str, include_stale: bool) -> Result<()> {
    info!("Fetching network status from {}", server);

    let identity = load_or_generate_identity(config).await?;
    let client = FileTransferClient::new(identity, config.storage.chunk_size);

    let mut grpc_client = client.connect(server).await?;
    let status = client.get_network_status(&mut grpc_client, include_stale).await?;

    println!("\n╔═══════════════════════════════════════════════════════════════╗");
    println!("║               NETWORK STATUS - CONNECTED NODES                ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║ Total Nodes: {:47} ║", status.total_nodes);

    if let Some(current) = &status.current_node {
        println!("║ Current Node: {:46} ║", current.node_id);
        println!("║ Address: {:51} ║", current.address);
    }

    println!("╠═══════════════════════════════════════════════════════════════╣");
    println!("║                      ACTIVE NODES                             ║");
    println!("╠═══════════════════════════════════════════════════════════════╣");

    if status.active_nodes.is_empty() {
        println!("║ No active nodes found                                         ║");
    } else {
        for (idx, node) in status.active_nodes.iter().enumerate() {
            println!("║                                                               ║");
            println!("║ Node #{:<2}                                                    ║", idx + 1);
            println!("║ ├─ ID:      {:<48} ║", node.node_id);
            println!("║ ├─ Address: {:<48} ║", node.address);

            let last_seen = chrono::DateTime::from_timestamp(node.last_seen, 0)
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            println!("║ └─ Last Seen: {:<46} ║", last_seen);
        }
    }

    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    Ok(())
}

async fn load_or_generate_identity(config: &Config) -> Result<NodeIdentity> {
    // Try to load existing certificate
    if config.node.certificate_path.exists() && config.node.private_key_path.exists() {
        let certificate_pem = tokio::fs::read_to_string(&config.node.certificate_path).await?;
        let private_key_pem = tokio::fs::read_to_string(&config.node.private_key_path).await?;

        let address = CertificateManager::extract_address_from_cert(&certificate_pem)?;

        let pem = pem::parse(&certificate_pem)?;
        let cert = x509_parser::parse_x509_certificate(&pem.contents())?.1;
        let public_key = cert.public_key().subject_public_key.data.as_ref();
        let node_id = hex::encode(
            &ring::digest::digest(&ring::digest::SHA256, public_key).as_ref()[..16],
        );

        Ok(NodeIdentity::new(
            node_id,
            certificate_pem,
            address,
            Some(private_key_pem),
        ))
    } else {
        // Generate new certificate
        info!("Generating new certificate for node");

        let cert = CertificateManager::generate_node_certificate(
            &config.node.name,
            &config.node.listen_address,
        )?;

        // Ensure directory exists
        if let Some(parent) = config.node.certificate_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Save certificate and private key
        tokio::fs::write(&config.node.certificate_path, &cert.certificate_pem).await?;
        tokio::fs::write(&config.node.private_key_path, &cert.private_key_pem).await?;

        info!("Certificate saved to {}", config.node.certificate_path.display());

        Ok(NodeIdentity::new(
            cert.node_id,
            cert.certificate_pem,
            cert.address,
            Some(cert.private_key_pem),
        ))
    }
}

fn format_size(size: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = size as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    format!("{:.2} {}", size, UNITS[unit_idx])
}
