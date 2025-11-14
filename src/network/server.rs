use anyhow::{Context, Result};
use std::net::SocketAddr;
use tonic::transport::Server;
use tracing::info;

use crate::grpc::file_transfer::file_transfer_service_server::FileTransferServiceServer as GrpcFileTransferService;
use crate::grpc::FileTransferServiceImpl;
use crate::pki::{CertificateValidator, NodeIdentity};
use crate::registry::NodeRegistry;
use crate::storage::FileManager;

/// File transfer server
pub struct FileTransferServer {
    listen_address: SocketAddr,
    service: FileTransferServiceImpl,
}

impl FileTransferServer {
    /// Create a new file transfer server
    pub fn new(
        listen_address: SocketAddr,
        file_manager: FileManager,
        certificate_validator: CertificateValidator,
        node_registry: NodeRegistry,
        local_identity: NodeIdentity,
    ) -> Self {
        let service = FileTransferServiceImpl::new(
            file_manager,
            certificate_validator,
            node_registry,
            local_identity,
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
