mod auto_upload;
mod config;
mod grpc;
mod network;
mod pki;
mod registry;
mod storage;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use tracing_subscriber;

use config::Config;
use network::{FileTransferClient, FileTransferServer};
use pki::{CertificateManager, CertificateValidator, NodeIdentity};
use registry::{DistributedRegistry, NodeRegistry};
use storage::{FileManager, StorageConfig};

/// Get system config file path
fn get_system_config_path() -> PathBuf {
    PathBuf::from("/etc/uploader/config.toml")
}

/// Get development config file path (fallback)
fn get_dev_config_path() -> PathBuf {
    PathBuf::from("config.toml")
}

/// Discover config file with priority order
fn discover_config(cli_path: Option<PathBuf>) -> PathBuf {
    // Priority 1: CLI specified path (for development override)
    if let Some(path) = cli_path {
        warn!("Using custom config path: {}", path.display());
        return path;
    }

    // Priority 2: System config /etc/uploader/config.toml (production default)
    let system_config = get_system_config_path();
    if system_config.exists() {
        return system_config;
    }

    // Priority 3: Development config ./config.toml (development fallback)
    let dev_config = get_dev_config_path();
    if dev_config.exists() {
        warn!("Using development config: {}", dev_config.display());
        return dev_config;
    }

    // No config found - will create system config by default
    system_config
}

#[derive(Parser)]
#[command(name = "uploader")]
#[command(about = "Distributed file transfer system with blockchain-based authentication")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Config file path
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Show version information
    #[arg(short = 'V', long = "version")]
    version: bool,
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

    /// Edit system configuration interactively
    EditConfig {
        /// Configuration file path
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Show version information
    Version,

    /// Start the server
    Server,

    /// Run auto upload daemon
    AutoUpload,

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

/// Get Rust compiler version
fn get_rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Handle version flag
    if cli.version {
        show_version();
        return Ok(());
    }

    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    match cli.command {
        Some(Commands::GenCert {
            name,
            address,
            cert_out,
            key_out,
        }) => {
            generate_certificate(&name, &address, &cert_out, &key_out).await?;
        }

        Some(Commands::EditConfig { config }) => {
            let config_path = if let Some(path) = config {
                path
            } else {
                discover_config(cli.config)
            };
            edit_config_interactively(&config_path).await?;
        }

        Some(Commands::Version) => {
            show_version();
        }

        Some(Commands::Server) => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)
                .context("Failed to load config. Run 'uploader edit-config' first")?;

            run_server(config).await?;
        }

        Some(Commands::AutoUpload) => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)
                .context("Failed to load config. Run 'uploader edit-config' first")?;

            run_auto_upload(config).await?;
        }

        Some(Commands::Upload {
            file,
            servers,
            mime_type,
        }) => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)?;
            upload_file(&config, &file, &servers, mime_type).await?;
        }

        Some(Commands::Download {
            server,
            file_id,
            output,
        }) => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)?;
            download_file(&config, &server, &file_id, &output).await?;
        }

        Some(Commands::List {
            server,
            source_ip,
            page,
            page_size,
        }) => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)?;
            list_files(&config, &server, source_ip, page, page_size).await?;
        }

        Some(Commands::Ping { server }) => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)?;
            ping_server(&config, &server).await?;
        }

        Some(Commands::ListNodes {
            server,
            include_stale,
        }) => {
            let config_path = discover_config(cli.config);
            let config = Config::from_file(&config_path)?;
            list_nodes(&config, &server, include_stale).await?;
        }
        None => {
            error!("No command provided. Use --help for usage information.");
            std::process::exit(1);
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

async fn edit_config_interactively(config_path: &Path) -> Result<()> {

    println!("🔧 Interactive Configuration Editor");
    println!("================================");
    println!("Config file: {}", config_path.display());
    println!();

    // Check if config exists
    let mut config = if config_path.exists() {
        println!("📄 Loading existing configuration...");
        Config::from_file(&config_path)
            .context("Failed to load existing config")?
    } else {
        println!("📄 No existing config found. Creating default configuration...");
        Config::default()
    };

    println!();

    // Edit node configuration
    println!("🖥️  Node Configuration");
    println!("---------------------");
    println!("Current node name: {}", config.node.name);
    print!("Enter node name [{}]: ", config.node.name);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if !input.is_empty() {
        config.node.name = input.to_string();
    }

    println!("Current listen address: {}", config.node.listen_address);
    print!("Enter listen address [{}]: ", config.node.listen_address);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if !input.is_empty() {
        match input.parse() {
            Ok(addr) => config.node.listen_address = addr,
            Err(_) => println!("⚠️  Invalid address format, keeping current value"),
        }
    }

    println!();

    // Edit network configuration
    println!("🌐 Network Configuration");
    println!("------------------------");
    println!("Current P2P port: {}", config.network.p2p_port);
    print!("Enter P2P port [{}]: ", config.network.p2p_port);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if !input.is_empty() {
        match input.parse() {
            Ok(port) => config.network.p2p_port = port,
            Err(_) => println!("⚠️  Invalid port number, keeping current value"),
        }
    }

    println!("Current bootstrap nodes: {:?}", config.network.bootstrap_nodes);
    print!("Enter bootstrap nodes (comma-separated, blank for none): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if !input.is_empty() {
        config.network.bootstrap_nodes = input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    println!();

    // Edit security configuration
    println!("🔒 Security Configuration");
    println!("------------------------");

    // Network secret - always ask this for security
    if let Some(ref secret) = config.security.network_secret {
        println!("Current network secret: [REDACTED]");
    } else {
        println!("Current network secret: [NOT SET - INSECURE!]");
    }

    print!("Enter network secret (required for production): ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if !input.is_empty() {
        config.security.network_secret = if input == "NONE" {
            None
        } else {
            Some(input.to_string())
        };
    } else if config.security.network_secret.is_none() {
        println!("⚠️  WARNING: No network secret set - this is insecure for production!");
    }

    println!("Current allow self-signed certificates: {}", config.security.allow_self_signed);
    print!("Allow self-signed certificates? (y/n) [{}]: ",
        if config.security.allow_self_signed { "y" } else { "n" });
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();
    if !input.is_empty() {
        config.security.allow_self_signed = matches!(input.as_str(), "y" | "yes" | "true" | "1");
    }

    println!("Current require mTLS: {}", config.security.require_mtls);
    print!("Require mutual TLS? (y/n) [{}]: ",
        if config.security.require_mtls { "y" } else { "n" });
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();
    if !input.is_empty() {
        config.security.require_mtls = matches!(input.as_str(), "y" | "yes" | "true" | "1");
    }

    println!();

    // Edit ID management configuration
    println!("🆔 ID Management Configuration");
    println!("-----------------------------");
    println!("Current enabled: {}", config.network_ids.enabled);
    print!("Enable ID management? (y/n) [{}]: ",
        if config.network_ids.enabled { "y" } else { "n" });
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();
    if !input.is_empty() {
        config.network_ids.enabled = matches!(input.as_str(), "y" | "yes" | "true" | "1");
    }

    println!();

    // Edit storage configuration
    println!("💾 Storage Configuration");
    println!("------------------------");
    println!("Current storage root: {}", config.storage.root_dir.display());
    print!("Enter storage root directory [{}]: ", config.storage.root_dir.display());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if !input.is_empty() {
        config.storage.root_dir = PathBuf::from(input);
    }

    println!("Current chunk size: {} bytes", config.storage.chunk_size);
    print!("Enter chunk size in bytes [{}]: ", config.storage.chunk_size);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if !input.is_empty() {
        match input.parse() {
            Ok(size) => {
                if size > 0 {
                    config.storage.chunk_size = size;
                } else {
                    println!("⚠️  Chunk size must be greater than 0");
                }
            },
            Err(_) => println!("⚠️  Invalid number, keeping current value"),
        }
    }

    println!();

    // Certificate paths
    println!("📜 Certificate Configuration");
    println!("---------------------------");
    println!("Current certificate path: {}", config.node.certificate_path.display());
    print!("Enter certificate path [{}]: ", config.node.certificate_path.display());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if !input.is_empty() {
        config.node.certificate_path = PathBuf::from(input);
    }

    println!("Current private key path: {}", config.node.private_key_path.display());
    print!("Enter private key path [{}]: ", config.node.private_key_path.display());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    if !input.is_empty() {
        config.node.private_key_path = PathBuf::from(input);
    }

    println!();

    // Edit auto upload configuration
    println!("🔄 Auto Upload Configuration");
    println!("=============================");
    println!("Current enabled: {}", config.auto_upload.enabled);
    print!("Enable auto upload? (y/n) [{}]: ",
        if config.auto_upload.enabled { "y" } else { "n" });
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();
    if !input.is_empty() {
        config.auto_upload.enabled = matches!(input.as_str(), "y" | "yes" | "true" | "1");
    }

    if config.auto_upload.enabled {
        // Watch folder
        println!("Current watch folder: {}", config.auto_upload.watch_folder.display());
        print!("Enter watch folder [{}]: ", config.auto_upload.watch_folder.display());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if !input.is_empty() {
            config.auto_upload.watch_folder = PathBuf::from(input);
        }

        // Scan interval
        println!("Current scan interval: {} seconds", config.auto_upload.scan_interval_seconds);
        print!("Enter scan interval in seconds [{}]: ", config.auto_upload.scan_interval_seconds);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if !input.is_empty() {
            config.auto_upload.scan_interval_seconds = input.parse()
                .context("Invalid scan interval (must be a number)")?;
        }

        // Destination servers
        println!("Current destination servers: {:?}", config.auto_upload.destination_servers);
        print!("Enter destination servers (comma-separated) [{}]: ",
            config.auto_upload.destination_servers.join(","));
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if !input.is_empty() {
            config.auto_upload.destination_servers = input
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }

        // File extensions
        println!("Current file extensions: {:?}", config.auto_upload.file_extensions);
        print!("Enter file extensions to monitor (comma-separated, blank for all) [{}]: ",
            config.auto_upload.file_extensions.join(","));
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if !input.is_empty() {
            config.auto_upload.file_extensions = input
                .split(',')
                .map(|s| {
                    let ext = s.trim();
                    if ext.starts_with('.') {
                        ext.to_string()
                    } else {
                        format!(".{}", ext)
                    }
                })
                .collect();
        }

        // Max file size
        println!("Current max file size: {} bytes", config.auto_upload.max_file_size);
        print!("Enter max file size in bytes (0 for unlimited) [{}]: ", config.auto_upload.max_file_size);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if !input.is_empty() {
            config.auto_upload.max_file_size = input.parse()
                .context("Invalid max file size (must be a number)")?;
        }

        // Rename after upload
        println!("Current rename after upload: {}", config.auto_upload.rename_after_upload);
        print!("Rename files after successful upload? (y/n) [{}]: ",
            if config.auto_upload.rename_after_upload { "y" } else { "n" });
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim().to_lowercase();
        if !input.is_empty() {
            config.auto_upload.rename_after_upload = matches!(input.as_str(), "y" | "yes" | "true" | "1");
        }

        // Upload suffix
        println!("Current upload suffix: {}", config.auto_upload.upload_suffix);
        print!("Enter upload suffix [{}]: ", config.auto_upload.upload_suffix);
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if !input.is_empty() {
            config.auto_upload.upload_suffix = input.to_string();
        }
    }

    println!();

    // Show final configuration summary
    println!("📋 Configuration Summary");
    println!("========================");
    println!("Node name: {}", config.node.name);
    println!("Listen address: {}", config.node.listen_address);
    println!("P2P port: {}", config.network.p2p_port);
    println!("Bootstrap nodes: {:?}", config.network.bootstrap_nodes);
    println!("Network secret: {}",
        if config.security.network_secret.is_some() { "[SET]" } else { "[NOT SET - INSECURE!]" });
    println!("Allow self-signed: {}", config.security.allow_self_signed);
    println!("Require mTLS: {}", config.security.require_mtls);
    println!("ID management enabled: {}", config.network_ids.enabled);
    println!("Storage root: {}", config.storage.root_dir.display());
    println!("Chunk size: {} bytes", config.storage.chunk_size);
    println!("Certificate path: {}", config.node.certificate_path.display());
    println!("Private key path: {}", config.node.private_key_path.display());
    println!("Auto upload enabled: {}", config.auto_upload.enabled);
    if config.auto_upload.enabled {
        println!("  Watch folder: {}", config.auto_upload.watch_folder.display());
        println!("  Scan interval: {} seconds", config.auto_upload.scan_interval_seconds);
        println!("  Destination servers: {:?}", config.auto_upload.destination_servers);
        println!("  File extensions: {:?}", config.auto_upload.file_extensions);
        println!("  Max file size: {} bytes", config.auto_upload.max_file_size);
        println!("  Rename after upload: {}", config.auto_upload.rename_after_upload);
        println!("  Upload suffix: {}", config.auto_upload.upload_suffix);
    }
    println!();

    print!("Save this configuration to {}? (y/n): ", config_path.display());
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    if matches!(input.as_str(), "y" | "yes" | "true" | "1") {
        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            tokio::fs::create_dir_all(parent).await
                .context("Failed to create config directory")?;
        }

        config.to_file(&config_path)
            .context("Failed to save configuration")?;

        println!("✅ Configuration saved to {}", config_path.display());

        // Validate and ensure directories
        if let Err(e) = config.validate() {
            println!("⚠️  Configuration validation warning: {}", e);
        }

        if let Err(e) = config.ensure_directories() {
            println!("⚠️  Directory creation warning: {}", e);
        } else {
            println!("✅ Configuration directories ensured");
        }

        println!("🎉 Configuration setup complete!");
        println!("💡 You can now start the server with: uploader server");
    } else {
        println!("❌ Configuration not saved");
    }

    Ok(())
}

fn show_version() {
    println!("🚀 Uploader Distributed File Transfer System");
    println!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Get commit hash if available
    let commit_hash = option_env!("VERGEN_GIT_SHA");
    let build_date = option_env!("VERGEN_BUILD_DATE");

    if let Some(hash) = commit_hash {
        println!("Git Commit: {}", hash);
    }

    if let Some(date) = build_date {
        println!("Build Date: {}", date);
    }

    println!("Rust Version: {}", get_rustc_version());
    println!("Binary: {}", std::env::current_exe().unwrap_or_else(|_| PathBuf::from("unknown")).display());
    println!();
    println!("📋 Configuration:");

    // Try to show config location
    let config_paths = vec![
        get_system_config_path(),
        get_dev_config_path(),
    ];

    for (i, path) in config_paths.iter().enumerate() {
        let status = if path.exists() { "✅" } else { "❌" };
        println!("  {}. Config: {} {}", i + 1, status, path.display());
    }

    println!();
    println!("🔧 Features:");
    println!("  ✅ Distributed file transfer");
    println!("  ✅ gRPC communication");
    println!("  ✅ Mutual TLS authentication");
    println!("  ✅ Interactive configuration");
    println!("  ✅ Network ID management");
    println!("  ✅ Enhanced logging");
    println!();
    println!("📚 Documentation:");
    println!("  https://github.com/your-username/uploader");
    println!();
}

async fn run_auto_upload(config: Config) -> Result<()> {
    use auto_upload::FileWatcher;

    info!("🔄 Starting auto upload daemon");

    // Validate auto upload config
    if !config.auto_upload.enabled {
        return Err(anyhow::anyhow!("Auto upload is not enabled in config"));
    }

    if config.auto_upload.destination_servers.is_empty() {
        return Err(anyhow::anyhow!("No destination servers configured for auto upload"));
    }

    // Load or generate identity
    let identity = load_or_generate_identity(&config).await?;

    info!("Node ID: {}", identity.node_id);
    info!("Watch folder: {}", config.auto_upload.watch_folder.display());
    info!("Destination servers: {:?}", config.auto_upload.destination_servers);

    // Create file transfer client
    let client = FileTransferClient::new(identity.clone(), config.storage.chunk_size);

    // Create and start file watcher
    let file_watcher = FileWatcher::new(config.auto_upload, client, identity);
    file_watcher.start().await?;

    Ok(())
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
