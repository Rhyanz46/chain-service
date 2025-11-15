use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use super::file_transfer::{
    file_transfer_service_server::FileTransferService,
    AssignFirstNodeIdRequest, AssignNodeIdResponse, AuthRequest, AuthResponse,
    CheckIpReclamationRequest, CheckIpReclamationResponse, ConfirmIdAssignmentRequest,
    ConfirmIdAssignmentResponse, DownloadRequest, FileChunk, FileInfo,
    FileMetadata as ProtoFileMetadata, ListFilesRequest, ListFilesResponse,
    NodeInfo as ProtoNodeInfo, PingRequest, PingResponse, ReserveNodeIdRequest,
    ReserveNodeIdResponse, SyncNetworkStateRequest, SyncNetworkStateResponse,
    UploadResponse,
};
use crate::config::{SecurityConfig, NetworkIdConfig};
use crate::network::NetworkIdManager;
use crate::pki::{CertificateManager, CertificateValidator, NodeIdentity};
use crate::registry::NodeRegistry;
use crate::storage::{FileManager, NetworkDatabase};

type ResponseStream = Pin<Box<dyn Stream<Item = Result<FileChunk, Status>> + Send>>;

/// gRPC service implementation for file transfer
pub struct FileTransferServiceImpl {
    file_manager: Arc<FileManager>,
    certificate_validator: Arc<CertificateValidator>,
    node_registry: Arc<NodeRegistry>,
    local_identity: Arc<NodeIdentity>,
    security_config: Arc<SecurityConfig>,

    // ID Management (optional, only when enabled)
    id_manager: Option<Arc<NetworkIdManager>>,
    network_db: Option<Arc<RwLock<NetworkDatabase>>>,
    id_config: Option<Arc<NetworkIdConfig>>,
}

impl FileTransferServiceImpl {
    /// Create new service with ID management enabled
    pub fn new_with_id_management(
        file_manager: FileManager,
        certificate_validator: CertificateValidator,
        node_registry: NodeRegistry,
        local_identity: NodeIdentity,
        security_config: SecurityConfig,
        id_manager: NetworkIdManager,
        network_db: NetworkDatabase,
        id_config: NetworkIdConfig,
    ) -> Self {
        Self {
            file_manager: Arc::new(file_manager),
            certificate_validator: Arc::new(certificate_validator),
            node_registry: Arc::new(node_registry),
            local_identity: Arc::new(local_identity),
            security_config: Arc::new(security_config),
            id_manager: Some(Arc::new(id_manager)),
            network_db: Some(Arc::new(RwLock::new(network_db))),
            id_config: Some(Arc::new(id_config)),
        }
    }

    /// Create new service (legacy mode without ID management)
    pub fn new(
        file_manager: FileManager,
        certificate_validator: CertificateValidator,
        node_registry: NodeRegistry,
        local_identity: NodeIdentity,
        security_config: SecurityConfig,
    ) -> Self {
        Self {
            file_manager: Arc::new(file_manager),
            certificate_validator: Arc::new(certificate_validator),
            node_registry: Arc::new(node_registry),
            local_identity: Arc::new(local_identity),
            security_config: Arc::new(security_config),
            id_manager: None,
            network_db: None,
            id_config: None,
        }
    }

    /// Check if ID management is enabled
    fn is_id_management_enabled(&self) -> bool {
        self.id_manager.is_some() && self.network_db.is_some() && self.id_config.is_some()
    }

    /// Extract client IP from request
    fn get_client_ip(&self, request: &Request<impl std::any::Any>) -> Result<IpAddr, Status> {
        Ok(request
            .remote_addr()
            .ok_or_else(|| Status::internal("Failed to get client address"))?
            .ip())
    }

    /// Authenticate a request by verifying the certificate
    fn authenticate_request(
        &self,
        request: &Request<impl std::any::Any>,
    ) -> Result<String, Status> {
        // Extract certificate from metadata
        let metadata = request.metadata();

        let cert_pem = metadata
            .get("x-certificate")
            .ok_or_else(|| Status::unauthenticated("Missing certificate"))?
            .to_str()
            .map_err(|_| Status::unauthenticated("Invalid certificate format"))?;

        // Validate certificate
        let validation_result = self
            .certificate_validator
            .validate_certificate(cert_pem)
            .map_err(|e| Status::internal(format!("Certificate validation failed: {}", e)))?;

        if !validation_result.valid {
            return Err(Status::unauthenticated(format!(
                "Invalid certificate: {:?}",
                validation_result.reason
            )));
        }

        // Extract address from certificate
        let cert_address = CertificateManager::extract_address_from_cert(cert_pem)
            .map_err(|e| Status::internal(format!("Failed to extract address: {}", e)))?;

        // Verify the request is coming from the correct IP
        let client_ip = self.get_client_ip(request)?;
        if client_ip != cert_address.ip() {
            return Err(Status::unauthenticated(format!(
                "IP mismatch: certificate={}, actual={}",
                cert_address.ip(),
                client_ip
            )));
        }

        // Get node ID from certificate
        let pem = pem::parse(cert_pem)
            .map_err(|e| Status::internal(format!("Failed to parse certificate: {}", e)))?;
        let cert = x509_parser::parse_x509_certificate(&pem.contents())
            .map_err(|e| Status::internal(format!("Failed to parse X509: {}", e)))?
            .1;

        let public_key = cert.public_key().subject_public_key.data.as_ref();
        let node_id = hex::encode(&ring::digest::digest(&ring::digest::SHA256, public_key).as_ref()[..16]);

        Ok(node_id)
    }
}

#[tonic::async_trait]
impl FileTransferService for FileTransferServiceImpl {
    async fn upload_file(
        &self,
        request: Request<tonic::Streaming<FileChunk>>,
    ) -> Result<Response<UploadResponse>, Status> {
        let _node_id = self.authenticate_request(&request)?;
        let client_ip = self.get_client_ip(&request)?;

        info!("Receiving file upload from {}", client_ip);

        let mut stream = request.into_inner();
        let mut writer: Option<crate::storage::file_manager::FileWriter> = None;
        let mut total_bytes = 0u64;
        let mut file_id = String::new();

        // Process chunks
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;

            // First chunk contains metadata
            if writer.is_none() {
                let metadata = chunk
                    .metadata
                    .ok_or_else(|| Status::invalid_argument("First chunk must contain metadata"))?;

                let file_writer = self
                    .file_manager
                    .start_write(
                        metadata.filename.clone(),
                        client_ip,
                        metadata.file_size,
                        metadata.mime_type.clone(),
                    )
                    .await
                    .map_err(|e| Status::internal(format!("Failed to start write: {}", e)))?;

                file_id = file_writer.file_id.clone();
                writer = Some(file_writer);
            }

            // Write chunk data
            if !chunk.data.is_empty() {
                let w = writer
                    .as_mut()
                    .ok_or_else(|| Status::internal("Writer not initialized"))?;

                w.write_chunk(&chunk.data)
                    .await
                    .map_err(|e| Status::internal(format!("Failed to write chunk: {}", e)))?;

                total_bytes += chunk.data.len() as u64;
            }
        }

        // Finalize
        if let Some(w) = writer {
            w.finalize(&self.file_manager)
                .await
                .map_err(|e| Status::internal(format!("Failed to finalize: {}", e)))?;

            info!(
                "Upload complete: {} bytes from {} (ID: {})",
                total_bytes, client_ip, file_id
            );

            Ok(Response::new(UploadResponse {
                success: true,
                message: "Upload successful".to_string(),
                file_id,
                bytes_received: total_bytes,
            }))
        } else {
            Err(Status::invalid_argument("No data received"))
        }
    }

    type DownloadFileStream = ResponseStream;

    async fn download_file(
        &self,
        request: Request<DownloadRequest>,
    ) -> Result<Response<Self::DownloadFileStream>, Status> {
        let _node_id = self.authenticate_request(&request)?;
        let req = request.into_inner();

        info!("Serving file download: {}", req.file_id);

        // Parse file_id to extract source IP (format: hash or ip/hash)
        let parts: Vec<&str> = req.file_id.split('/').collect();
        let (source_ip_str, file_id) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            return Err(Status::invalid_argument(
                "file_id must be in format: source_ip/file_id",
            ));
        };

        let source_ip: IpAddr = source_ip_str
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid source IP"))?;

        let file_manager = Arc::clone(&self.file_manager);
        let mut reader = file_manager
            .start_read(file_id, &source_ip)
            .await
            .map_err(|e| Status::not_found(format!("File not found: {}", e)))?;

        let metadata = reader.metadata.clone();

        // Create stream
        let stream = async_stream::stream! {
            let mut chunk_number = 0u64;
            let total_chunks = (metadata.file_size + 1023) / 1024; // Rough estimate

            // Send first chunk with metadata
            let first_data = reader
                .read_chunk()
                .await
                .map_err(|e| Status::internal(format!("Read error: {}", e)))?;

            if let Some(data) = first_data {
                yield Ok(FileChunk {
                    metadata: Some(ProtoFileMetadata {
                        filename: metadata.filename.clone(),
                        file_size: metadata.file_size,
                        mime_type: metadata.mime_type.clone(),
                        source_ip: metadata.source_ip.clone(),
                        timestamp: metadata.timestamp,
                        checksum: metadata.checksum.clone(),
                    }),
                    data,
                    chunk_number,
                    total_chunks: Some(total_chunks),
                });
                chunk_number += 1;
            }

            // Stream remaining chunks
            while let Some(data) = reader
                .read_chunk()
                .await
                .map_err(|e| Status::internal(format!("Read error: {}", e)))?
            {
                yield Ok(FileChunk {
                    metadata: None,
                    data,
                    chunk_number,
                    total_chunks: None,
                });
                chunk_number += 1;
            }
        };

        Ok(Response::new(Box::pin(stream) as Self::DownloadFileStream))
    }

    async fn list_files(
        &self,
        request: Request<ListFilesRequest>,
    ) -> Result<Response<ListFilesResponse>, Status> {
        let _node_id = self.authenticate_request(&request)?;
        let req = request.into_inner();

        let files = if let Some(source_ip_str) = req.source_ip {
            let source_ip: IpAddr = source_ip_str
                .parse()
                .map_err(|_| Status::invalid_argument("Invalid source IP"))?;

            self.file_manager
                .list_files(&source_ip)
                .await
                .map_err(|e| Status::internal(format!("Failed to list files: {}", e)))?
        } else {
            self.file_manager
                .list_all_files()
                .await
                .map_err(|e| Status::internal(format!("Failed to list files: {}", e)))?
        };

        let total_count = files.len() as u32;

        // Apply pagination
        let page = req.page.max(1);
        let page_size = req.page_size.max(1).min(100);
        let start = ((page - 1) * page_size) as usize;
        let end = (start + page_size as usize).min(files.len());

        let paginated_files: Vec<FileInfo> = files[start..end]
            .iter()
            .map(|f| FileInfo {
                file_id: format!("{}/{}", f.metadata.source_ip, f.file_id),
                metadata: Some(ProtoFileMetadata {
                    filename: f.metadata.filename.clone(),
                    file_size: f.metadata.file_size,
                    mime_type: f.metadata.mime_type.clone(),
                    source_ip: f.metadata.source_ip.clone(),
                    timestamp: f.metadata.timestamp,
                    checksum: f.metadata.checksum.clone(),
                }),
                storage_path: f.storage_path.to_string_lossy().to_string(),
            })
            .collect();

        Ok(Response::new(ListFilesResponse {
            files: paginated_files,
            total_count,
        }))
    }

    async fn authenticate(
        &self,
        request: Request<AuthRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();

        info!("Authentication request from {}", req.node_address);

        // Validate certificate
        let validation_result = self
            .certificate_validator
            .validate_certificate(&req.certificate)
            .map_err(|e| Status::internal(format!("Validation failed: {}", e)))?;

        if !validation_result.valid {
            warn!(
                "Authentication failed: {:?}",
                validation_result.reason
            );

            return Ok(Response::new(AuthResponse {
                authenticated: false,
                message: format!("Authentication failed: {:?}", validation_result.reason),
                challenge: Vec::new(),
                known_nodes: Vec::new(),
            }));
        }

        // Extract address from certificate
        let cert_address = CertificateManager::extract_address_from_cert(&req.certificate)
            .map_err(|e| Status::internal(format!("Failed to extract address: {}", e)))?;

        // Verify signature (challenge-response)
        let challenge_data = format!("{}:{}", req.node_address, req.timestamp);
        let signature_valid = self
            .certificate_validator
            .verify_challenge(&req.certificate, challenge_data.as_bytes(), &req.signature)
            .map_err(|e| Status::internal(format!("Signature verification failed: {}", e)))?;

        if !signature_valid {
            warn!("Invalid signature from {}", req.node_address);

            return Ok(Response::new(AuthResponse {
                authenticated: false,
                message: "Invalid signature".to_string(),
                challenge: Vec::new(),
                known_nodes: Vec::new(),
            }));
        }

        // Add to trusted certificates
        self.certificate_validator
            .add_trusted_certificate(&req.certificate)
            .map_err(|e| Status::internal(format!("Failed to add certificate: {}", e)))?;

        // Register node in registry
        let node_id = hex::encode(
            &ring::digest::digest(
                &ring::digest::SHA256,
                req.certificate.as_bytes(),
            )
            .as_ref()[..16],
        );

        let node_info = crate::registry::NodeInfo::new(
            node_id.clone(),
            req.certificate.clone(),
            cert_address,
        );

        self.node_registry
            .register_node(node_info)
            .map_err(|e| Status::internal(format!("Failed to register node: {}", e)))?;

        // Get list of known nodes
        let known_nodes = self
            .node_registry
            .get_active_nodes()
            .map_err(|e| Status::internal(format!("Failed to get nodes: {}", e)))?
            .into_iter()
            .map(|n| ProtoNodeInfo {
                node_id: n.node_id,
                certificate: n.certificate,
                address: n.address.to_string(),
                last_seen: n.last_seen,
            })
            .collect();

        // Generate challenge for next authentication
        let challenge = ring::rand::SystemRandom::new();
        let mut challenge_bytes = vec![0u8; 32];
        ring::rand::SecureRandom::fill(&challenge, &mut challenge_bytes)
            .map_err(|_| Status::internal("Failed to generate challenge"))?;

        info!("Authentication successful for node {}", node_id);

        Ok(Response::new(AuthResponse {
            authenticated: true,
            message: "Authentication successful".to_string(),
            challenge: challenge_bytes,
            known_nodes,
        }))
    }

    async fn ping(&self, request: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let req = request.into_inner();

        Ok(Response::new(PingResponse {
            timestamp: req.timestamp,
            node_id: self.local_identity.node_id.clone(),
        }))
    }

    async fn get_network_status(
        &self,
        request: Request<super::file_transfer::NetworkStatusRequest>,
    ) -> Result<Response<super::file_transfer::NetworkStatusResponse>, Status> {
        let _node_id = self.authenticate_request(&request)?;
        let req = request.into_inner();

        info!("Network status requested");

        // Get active nodes
        let nodes = if req.include_stale {
            self.node_registry
                .get_all_nodes()
                .map_err(|e| Status::internal(format!("Failed to get nodes: {}", e)))?
        } else {
            self.node_registry
                .get_active_nodes()
                .map_err(|e| Status::internal(format!("Failed to get nodes: {}", e)))?
        };

        let active_nodes: Vec<ProtoNodeInfo> = nodes
            .iter()
            .map(|n| ProtoNodeInfo {
                node_id: n.node_id.clone(),
                certificate: n.certificate.clone(),
                address: n.address.to_string(),
                last_seen: n.last_seen,
            })
            .collect();

        let total_nodes = active_nodes.len() as u32;

        // Current node info
        let current_node = ProtoNodeInfo {
            node_id: self.local_identity.node_id.clone(),
            certificate: self.local_identity.certificate_pem.clone(),
            address: self.local_identity.address.to_string(),
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        };

        // Calculate uptime (simplified - should be tracked from server start)
        let uptime_seconds = 0; // TODO: Track actual uptime

        Ok(Response::new(super::file_transfer::NetworkStatusResponse {
            active_nodes,
            total_nodes,
            current_node: Some(current_node),
            uptime_seconds,
        }))
    }

    async fn register_node(
        &self,
        request: Request<super::file_transfer::RegisterNodeRequest>,
    ) -> Result<Response<super::file_transfer::RegisterNodeResponse>, Status> {
        // 🔒 SECURITY CHECK 1: Get real client IP from connection (BEFORE consuming request)
        let client_ip = self.get_client_ip(&request)?;

        let req = request.into_inner();

        info!("Node registration request from {} (connecting from {})", req.address, client_ip);

        // 🔒 SECURITY CHECK 2: Verify network secret (if configured)
        if let Some(expected_secret) = &self.security_config.network_secret {
            if req.network_secret.is_empty() {
                warn!("Registration rejected: network secret required but not provided");
                return Err(Status::unauthenticated(
                    "Network secret required for registration"
                ));
            }

            if &req.network_secret != expected_secret {
                warn!("Registration rejected: invalid network secret from {}", req.address);
                return Err(Status::unauthenticated(
                    "Invalid network secret"
                ));
            }

            info!("Network secret verified ✓");
        }

        // Validate certificate
        let validation_result = self
            .certificate_validator
            .validate_certificate(&req.certificate)
            .map_err(|e| Status::internal(format!("Validation failed: {}", e)))?;

        if !validation_result.valid {
            warn!("Registration rejected: invalid certificate - {:?}", validation_result.reason);
            return Ok(Response::new(super::file_transfer::RegisterNodeResponse {
                success: false,
                message: format!("Invalid certificate: {:?}", validation_result.reason),
                known_nodes: Vec::new(),
            }));
        }

        // 🔒 SECURITY CHECK 3: Extract IP from certificate
        let cert_address = CertificateManager::extract_address_from_cert(&req.certificate)
            .map_err(|e| {
                warn!("Registration rejected: failed to extract address from certificate");
                Status::internal(format!("Failed to extract address from certificate: {}", e))
            })?;

        // 🔒 SECURITY CHECK 4: Verify IP matches (prevent IP impersonation)
        if client_ip != cert_address.ip() {
            warn!(
                "Registration rejected: IP mismatch! Certificate claims {}, but connecting from {}",
                cert_address.ip(),
                client_ip
            );
            return Err(Status::unauthenticated(format!(
                "IP mismatch: certificate claims {}, but you are connecting from {}",
                cert_address.ip(),
                client_ip
            )));
        }

        info!("IP verification passed: {} ✓", client_ip);

        // 🔒 SECURITY CHECK 5: Verify address in request matches certificate
        let request_address: std::net::SocketAddr = req
            .address
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid address format"))?;

        if request_address != cert_address {
            warn!(
                "Registration rejected: Address mismatch! Certificate: {}, Request: {}",
                cert_address,
                request_address
            );
            return Err(Status::unauthenticated(format!(
                "Address in request ({}) doesn't match certificate ({})",
                request_address,
                cert_address
            )));
        }

        // ✅ ALL SECURITY CHECKS PASSED - Register node
        let node_info = crate::registry::NodeInfo::new(
            req.node_id.clone(),
            req.certificate.clone(),
            cert_address,
        );

        self.node_registry
            .register_node(node_info)
            .map_err(|e| Status::internal(format!("Failed to register node: {}", e)))?;

        // Add to trusted certificates
        self.certificate_validator
            .add_trusted_certificate(&req.certificate)
            .map_err(|e| Status::internal(format!("Failed to add certificate: {}", e)))?;

        // Get list of known nodes
        let known_nodes = self
            .node_registry
            .get_active_nodes()
            .map_err(|e| Status::internal(format!("Failed to get nodes: {}", e)))?
            .into_iter()
            .map(|n| ProtoNodeInfo {
                node_id: n.node_id,
                certificate: n.certificate,
                address: n.address.to_string(),
                last_seen: n.last_seen,
            })
            .collect();

        info!("✅ Node {} registered successfully from {} (verified)", req.node_id, client_ip);

        Ok(Response::new(super::file_transfer::RegisterNodeResponse {
            success: true,
            message: "Node registered successfully".to_string(),
            known_nodes,
        }))
    }

    /// Assign first node ID (bootstrap network)
    async fn assign_first_node_id(
        &self,
        request: Request<AssignFirstNodeIdRequest>,
    ) -> Result<Response<AssignNodeIdResponse>, Status> {
        if !self.is_id_management_enabled() {
            return Err(Status::failed_precondition("ID management is not enabled"));
        }

        let client_ip = self.get_client_ip(&request)?;
        let req = request.into_inner();

        info!("First node ID assignment request from {} for ID {}", client_ip, req.requested_id);

        // Validate network secret if required
        if let Some(security_config) = self.security_config.network_secret.as_ref() {
            if req.network_secret.is_empty() {
                return Err(Status::unauthenticated("Network secret required"));
            }
            if req.network_secret != *security_config {
                return Err(Status::unauthenticated("Invalid network secret"));
            }
        }

        let id_manager = self.id_manager.as_ref().unwrap();
        let network_db = self.network_db.as_ref().unwrap();

        // Check if network is empty (no active assignments)
        let db = network_db.read().await;
        if !db.is_empty().await {
            return Err(Status::already_exists("Network already has nodes. Cannot assign bootstrap node ID."));
        }
        drop(db); // Explicitly drop the read lock

        // Validate certificate
        let validation_result = self.certificate_validator
            .validate_certificate(&req.certificate)
            .map_err(|e| Status::invalid_argument(format!("Certificate validation failed: {}", e)))?;

        if !validation_result.valid {
            return Err(Status::unauthenticated(format!("Invalid certificate: {:?}", validation_result.reason)));
        }

        // Extract and verify IP from certificate matches client IP
        let cert_address = CertificateManager::extract_address_from_cert(&req.certificate)
            .map_err(|e| Status::invalid_argument(format!("Failed to extract address from certificate: {}", e)))?;

        if cert_address.ip() != client_ip {
            return Err(Status::unauthenticated(format!("IP mismatch: certificate claims {}, connecting from {}", cert_address.ip(), client_ip)));
        }

        // Assign the first node ID
        let assigned_id = id_manager.assign_first_node_id(cert_address, &req.requested_id)
            .await
            .map_err(|e| Status::internal(format!("Failed to assign ID: {}", e)))?;

        // Store in database
        let assignment = crate::network::id_manager::NodeAssignment {
            node_id: assigned_id.clone(),
            ip_address: cert_address,
            assigned_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            certificate_fingerprint: validation_result.reason.unwrap_or_default(),
            network_type: id_manager.extract_network_type(&assigned_id),
        };

        network_db.write().await.add_assignment(assignment).await
            .map_err(|e| Status::internal(format!("Failed to store assignment: {}", e)))?;

        info!("✅ First node assigned ID: {} to {}", assigned_id, client_ip);

        Ok(Response::new(AssignNodeIdResponse {
            success: true,
            message: format!("Successfully assigned bootstrap node ID: {}", assigned_id),
            assigned_id: assigned_id.clone(),
            is_bootstrap: true,
            metadata: Some(crate::grpc::file_transfer::NetworkMetadata {
                created_at: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
                last_updated: 0,
                total_nodes_joined: 1,
                version: "1.0.0".to_string(),
                bootstrap_node: assigned_id,
            }),
        }))
    }

    /// Reserve node ID for new node
    async fn reserve_node_id(
        &self,
        request: Request<ReserveNodeIdRequest>,
    ) -> Result<Response<ReserveNodeIdResponse>, Status> {
        if !self.is_id_management_enabled() {
            return Err(Status::failed_precondition("ID management is not enabled"));
        }

        let client_ip = self.get_client_ip(&request)?;
        let req = request.into_inner();

        info!("ID reservation request from {} for network type {}", client_ip, req.network_type);

        // Validate network secret if required
        if let Some(security_config) = self.security_config.network_secret.as_ref() {
            if req.network_secret.is_empty() {
                return Err(Status::unauthenticated("Network secret required"));
            }
            if req.network_secret != *security_config {
                return Err(Status::unauthenticated("Invalid network secret"));
            }
        }

        // Validate certificate
        let validation_result = self.certificate_validator
            .validate_certificate(&req.certificate)
            .map_err(|e| Status::invalid_argument(format!("Certificate validation failed: {}", e)))?;

        if !validation_result.valid {
            return Err(Status::unauthenticated(format!("Invalid certificate: {:?}", validation_result.reason)));
        }

        // Extract and verify IP from certificate matches client IP
        let cert_address = CertificateManager::extract_address_from_cert(&req.certificate)
            .map_err(|e| Status::invalid_argument(format!("Failed to extract address from certificate: {}", e)))?;

        if cert_address.ip() != client_ip {
            return Err(Status::unauthenticated(format!("IP mismatch: certificate claims {}, connecting from {}", cert_address.ip(), client_ip)));
        }

        let id_manager = self.id_manager.as_ref().unwrap();
        let id_config = self.id_config.as_ref().unwrap();

        // Check for IP reclamation first
        if let Some(old_id) = id_manager.check_ip_reclamation(cert_address).await {
            info!("Found reclaimable ID: {} for IP {}", old_id, client_ip);
            return Ok(Response::new(ReserveNodeIdResponse {
                success: true,
                message: format!("ID {} is available for reclamation", old_id),
                reserved_id: old_id.clone(),
                expires_at: (std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() + id_config.reservation_timeout) as i64,
                timeout_seconds: id_config.reservation_timeout as i64,
            }));
        }

        // Reserve new ID
        let reserved_id = id_manager.reserve_id(cert_address, &req.network_type)
            .await
            .map_err(|e| Status::internal(format!("Failed to reserve ID: {}", e)))?;

        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + id_config.reservation_timeout;

        info!("ID {} reserved for {} (expires in {}s)", reserved_id, client_ip, id_config.reservation_timeout);

        Ok(Response::new(ReserveNodeIdResponse {
            success: true,
            message: format!("Successfully reserved ID: {}", reserved_id),
            reserved_id,
            expires_at: expires_at as i64,
            timeout_seconds: id_config.reservation_timeout as i64,
        }))
    }

    /// Confirm ID assignment
    async fn confirm_id_assignment(
        &self,
        request: Request<ConfirmIdAssignmentRequest>,
    ) -> Result<Response<ConfirmIdAssignmentResponse>, Status> {
        if !self.is_id_management_enabled() {
            return Err(Status::failed_precondition("ID management is not enabled"));
        }

        let client_ip = self.get_client_ip(&request)?;
        let req = request.into_inner();

        info!("ID assignment confirmation for {} from {}", req.reserved_id, client_ip);

        let id_manager = self.id_manager.as_ref().unwrap();
        let network_db = self.network_db.as_ref().unwrap();

        // Convert IpAddr to SocketAddr (use default port for assignment)
        let client_addr = std::net::SocketAddr::new(client_ip, 50051);

        // Confirm assignment in ID manager
        let assigned_id = id_manager.confirm_assignment(client_addr, &req.certificate_fingerprint)
            .await
            .map_err(|e| Status::internal(format!("Failed to confirm assignment: {}", e)))?;

        // Get assignment details for database storage
        let assignments = id_manager.get_all_assignments().await;
        let assignment = assignments.get(&assigned_id)
            .ok_or_else(|| Status::not_found("Assignment not found"))?;

        // Store in network database
        let db_assignment = crate::network::id_manager::NodeAssignment {
            node_id: assigned_id.clone(),
            ip_address: client_addr,
            assigned_at: assignment.assigned_at,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            certificate_fingerprint: req.certificate_fingerprint.clone(),
            network_type: assignment.network_type.clone(),
        };

        network_db.write().await.add_assignment(db_assignment).await
            .map_err(|e| Status::internal(format!("Failed to store assignment: {}", e)))?;

        info!("✅ ID assignment confirmed: {} for {}", assigned_id, client_ip);

        // Convert to protobuf format
        let proto_assignment = crate::grpc::file_transfer::NodeAssignment {
            node_id: assigned_id.clone(),
            ip_address: client_addr.to_string(),
            assigned_at: assignment.assigned_at as i64,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
            certificate_fingerprint: req.certificate_fingerprint.clone(),
            network_type: assignment.network_type.clone(),
        };

        Ok(Response::new(ConfirmIdAssignmentResponse {
            success: true,
            message: format!("Successfully confirmed ID assignment: {}", assigned_id),
            node_id: assigned_id.clone(),
            assignment_info: Some(proto_assignment),
        }))
    }

    /// Check IP for ID reclamation
    async fn check_ip_reclamation(
        &self,
        request: Request<CheckIpReclamationRequest>,
    ) -> Result<Response<CheckIpReclamationResponse>, Status> {
        if !self.is_id_management_enabled() {
            return Err(Status::failed_precondition("ID management is not enabled"));
        }

        let client_ip = self.get_client_ip(&request)?;
        let req = request.into_inner();

        info!("IP reclamation check for {}", client_ip);

        // Validate network secret if required
        if let Some(security_config) = self.security_config.network_secret.as_ref() {
            if req.network_secret.is_empty() {
                return Err(Status::unauthenticated("Network secret required"));
            }
            if req.network_secret != *security_config {
                return Err(Status::unauthenticated("Invalid network secret"));
            }
        }

        let id_manager = self.id_manager.as_ref().unwrap();
        let network_db = self.network_db.as_ref().unwrap();

        // Convert IpAddr to SocketAddr (use default port for reclamation check)
        let client_addr = std::net::SocketAddr::new(client_ip, 50051);

        // Check for reclaimable ID
        if let Some(old_id) = id_manager.check_ip_reclamation(client_addr).await {
            // Get assignment details to calculate offline duration
            let assignments = network_db.read().await.get_all_assignments().await;
            if let Some(assignment) = assignments.get(&old_id) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let offline_duration = now - assignment.last_seen;

                info!("Found reclaimable ID: {} for {} (offline for {}s)", old_id, client_ip, offline_duration);

                return Ok(Response::new(CheckIpReclamationResponse {
                    success: true,
                    message: format!("ID {} is available for reclamation (offline for {}s)", old_id, offline_duration),
                    old_id: old_id.clone(),
                    can_reclaim: true,
                    offline_duration_seconds: offline_duration as i64,
                }));
            }
        }

        info!("No reclaimable ID found for {}", client_ip);

        Ok(Response::new(CheckIpReclamationResponse {
            success: true,
            message: "No reclaimable ID found for this IP".to_string(),
            old_id: String::new(),
            can_reclaim: false,
            offline_duration_seconds: 0,
        }))
    }

    /// Sync network state
    async fn sync_network_state(
        &self,
        request: Request<SyncNetworkStateRequest>,
    ) -> Result<Response<SyncNetworkStateResponse>, Status> {
        if !self.is_id_management_enabled() {
            return Err(Status::failed_precondition("ID management is not enabled"));
        }

        let req = request.into_inner();

        info!("Network state sync request (assignments: {}, last sync: {})",
              req.assignments_count, req.last_sync_timestamp);

        // Validate network secret if required
        if let Some(security_config) = self.security_config.network_secret.as_ref() {
            if req.network_secret.is_empty() {
                return Err(Status::unauthenticated("Network secret required"));
            }
            if req.network_secret != *security_config {
                return Err(Status::unauthenticated("Invalid network secret"));
            }
        }

        let network_db = self.network_db.as_ref().unwrap();
        let id_config = self.id_config.as_ref().unwrap();

        // Get current assignments and metadata
        let assignments = network_db.read().await.get_all_assignments().await;
        let metadata = network_db.read().await.get_metadata().await;

        // Convert assignments to protobuf format
        let proto_assignments: Vec<crate::grpc::file_transfer::NodeAssignment> = assignments
            .values()
            .map(|assignment| crate::grpc::file_transfer::NodeAssignment {
                node_id: assignment.node_id.clone(),
                ip_address: assignment.ip_address.to_string(),
                assigned_at: assignment.assigned_at as i64,
                last_seen: assignment.last_seen as i64,
                certificate_fingerprint: assignment.certificate_fingerprint.clone(),
                network_type: assignment.network_type.clone(),
            })
            .collect();

        // Find stale nodes (offline > threshold)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let stale_nodes: Vec<String> = assignments
            .iter()
            .filter(|(_, assignment)| now - assignment.last_seen > id_config.offline_threshold)
            .map(|(node_id, _)| node_id.clone())
            .collect();

        // Convert metadata to protobuf format
        let proto_metadata = crate::grpc::file_transfer::NetworkMetadata {
            created_at: metadata.created_at as i64,
            last_updated: metadata.last_updated as i64,
            total_nodes_joined: metadata.total_nodes_joined,
            version: metadata.version,
            bootstrap_node: metadata.bootstrap_node.unwrap_or_default(),
        };

        info!("Network state synced: {} assignments, {} stale nodes",
              proto_assignments.len(), stale_nodes.len());

        Ok(Response::new(SyncNetworkStateResponse {
            success: true,
            message: format!("Network state synced: {} assignments", proto_assignments.len()),
            assignments: proto_assignments,
            metadata: Some(proto_metadata),
            stale_nodes,
        }))
    }
}
