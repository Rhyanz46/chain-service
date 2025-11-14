pub mod certificate;
pub mod validator;

pub use certificate::{CertificateManager, NodeCertificate};
pub use validator::CertificateValidator;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Node identity containing certificate and address information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Unique node ID (derived from public key)
    pub node_id: String,

    /// PEM-encoded certificate
    pub certificate_pem: String,

    /// Node's network address
    pub address: SocketAddr,

    /// PEM-encoded private key (only stored locally)
    #[serde(skip_serializing)]
    pub private_key_pem: Option<String>,
}

impl NodeIdentity {
    /// Create a new node identity
    pub fn new(
        node_id: String,
        certificate_pem: String,
        address: SocketAddr,
        private_key_pem: Option<String>,
    ) -> Self {
        Self {
            node_id,
            certificate_pem,
            address,
            private_key_pem,
        }
    }

    /// Get the node ID
    pub fn id(&self) -> &str {
        &self.node_id
    }

    /// Get the certificate PEM
    pub fn certificate(&self) -> &str {
        &self.certificate_pem
    }

    /// Get the address
    pub fn address(&self) -> &SocketAddr {
        &self.address
    }
}
