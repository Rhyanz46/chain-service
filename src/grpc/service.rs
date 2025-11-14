use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};
use tracing::{error, info, warn};

use super::file_transfer::{
    file_transfer_service_server::FileTransferService, AuthRequest, AuthResponse, DownloadRequest,
    FileChunk, FileInfo, FileMetadata as ProtoFileMetadata, ListFilesRequest, ListFilesResponse,
    NodeInfo as ProtoNodeInfo, PingRequest, PingResponse, UploadResponse,
};
use crate::pki::{CertificateManager, CertificateValidator, NodeIdentity};
use crate::registry::NodeRegistry;
use crate::storage::{FileManager, FileMetadata};

type ResponseStream = Pin<Box<dyn Stream<Item = Result<FileChunk, Status>> + Send>>;

/// gRPC service implementation for file transfer
pub struct FileTransferServiceImpl {
    file_manager: Arc<FileManager>,
    certificate_validator: Arc<CertificateValidator>,
    node_registry: Arc<NodeRegistry>,
    local_identity: Arc<NodeIdentity>,
}

impl FileTransferServiceImpl {
    pub fn new(
        file_manager: FileManager,
        certificate_validator: CertificateValidator,
        node_registry: NodeRegistry,
        local_identity: NodeIdentity,
    ) -> Self {
        Self {
            file_manager: Arc::new(file_manager),
            certificate_validator: Arc::new(certificate_validator),
            node_registry: Arc::new(node_registry),
            local_identity: Arc::new(local_identity),
        }
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
}
