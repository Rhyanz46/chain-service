use anyhow::{Context, Result};
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::info;

use crate::config::{SecurityConfig, NetworkIdConfig};
use crate::grpc::file_transfer::file_transfer_service_server::FileTransferServiceServer as GrpcFileTransferService;
use crate::grpc::FileTransferServiceImpl;
use crate::network::NetworkIdManager;
use crate::pki::{CertificateValidator, NodeIdentity};
use crate::registry::NodeRegistry;
use crate::storage::{FileManager, NetworkDatabase};

/// File transfer server
pub struct FileTransferServer {
    listen_address: SocketAddr,
    service: FileTransferServiceImpl,
}

impl FileTransferServer {
    /// Create a new file transfer server with ID management (when enabled)
    pub async fn new_with_id_management(
        listen_address: SocketAddr,
        file_manager: FileManager,
        certificate_validator: CertificateValidator,
        node_registry: NodeRegistry,
        local_identity: NodeIdentity,
        security_config: SecurityConfig,
        id_config: NetworkIdConfig,
    ) -> Result<Self> {
        // Initialize Network Database
        let db_path = id_config.state_db_path.clone();
        let network_db = NetworkDatabase::new(db_path).await?;
        info!("Network database initialized at {}", id_config.state_db_path.display());

        // Initialize ID Manager
        let id_manager = NetworkIdManager::new().await?;
        info!("Network ID Manager initialized with {} available IDs",
              id_manager.get_available_ids("MainNet").await.len());

        let service = FileTransferServiceImpl::new_with_id_management(
            file_manager,
            certificate_validator,
            node_registry,
            local_identity,
            security_config,
            id_manager,
            network_db,
            id_config,
        );

        Ok(Self {
            listen_address,
            service,
        })
    }

    /// Create a new file transfer server (legacy mode without ID management)
    pub fn new(
        listen_address: SocketAddr,
        file_manager: FileManager,
        certificate_validator: CertificateValidator,
        node_registry: NodeRegistry,
        local_identity: NodeIdentity,
        security_config: SecurityConfig,
    ) -> Self {
        let service = FileTransferServiceImpl::new(
            file_manager,
            certificate_validator,
            node_registry,
            local_identity,
            security_config,
        );

        Self {
            listen_address,
            service,
        }
    }

    /// Start the server
    pub async fn start(self) -> Result<()> {
        info!("Starting gRPC server on {}", self.listen_address);

        Server::builder()
            .add_service(GrpcFileTransferService::new(self.service))
            .serve(self.listen_address)
            .await
            .context("Server error")?;

        Ok(())
    }
}
