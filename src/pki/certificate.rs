use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    SanType, PKCS_ED25519,
};
use ring::signature;
use std::net::SocketAddr;

/// Certificate manager for generating and managing node certificates
pub struct CertificateManager;

impl CertificateManager {
    /// Generate a new self-signed certificate for a node
    /// The certificate will contain the IP address and port in the SAN extension
    pub fn generate_node_certificate(
        node_name: &str,
        address: &SocketAddr,
    ) -> Result<NodeCertificate> {
        let mut params = CertificateParams::default();

        // Set the subject name
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, node_name);
        distinguished_name.push(DnType::OrganizationName, "FileTransferNetwork");
        params.distinguished_name = distinguished_name;

        // Add IP to Subject Alternative Names
        params.subject_alt_names = vec![
            SanType::IpAddress(address.ip()),
        ];

        // Set validity period (1 year)
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2025, 12, 31);

        // This is a self-signed certificate (acts as its own CA)
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Add custom extension for port number (OID: 1.3.6.1.4.1.99999.1)
        let port_extension = format!("port:{}", address.port());
        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            &[1, 3, 6, 1, 4, 1, 99999, 1],
            port_extension.as_bytes().to_vec(),
        )];

        // Generate Ed25519 key pair
        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ED25519)?;

        // Generate the certificate
        let cert = params.self_signed(&key_pair)
            .context("Failed to generate certificate from params")?;

        // Get PEM-encoded certificate and private key
        let certificate_pem = cert.pem();
        let private_key_pem = key_pair.serialize_pem();

        // Derive node ID from public key
        let public_key = key_pair.public_key_raw();
        let node_id = Self::derive_node_id(&public_key);

        Ok(NodeCertificate {
            node_id,
            certificate_pem,
            private_key_pem,
            address: *address,
        })
    }

    /// Generate a CA certificate that can sign other certificates
    #[allow(dead_code)]
    pub fn generate_ca_certificate(ca_name: &str) -> Result<NodeCertificate> {
        let mut params = CertificateParams::default();

        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, ca_name);
        distinguished_name.push(DnType::OrganizationName, "FileTransferNetwork");
        params.distinguished_name = distinguished_name;

        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 12, 31);

        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ED25519)?;
        let cert = params.self_signed(&key_pair)
            .context("Failed to generate CA certificate")?;

        let certificate_pem = cert.pem();
        let private_key_pem = key_pair.serialize_pem();
        let public_key = key_pair.public_key_raw();
        let node_id = Self::derive_node_id(&public_key);

        Ok(NodeCertificate {
            node_id,
            certificate_pem,
            private_key_pem,
            address: "0.0.0.0:0".parse().unwrap(),
        })
    }

    /// Sign data with a private key
    pub fn sign_data(private_key_pem: &str, data: &[u8]) -> Result<Vec<u8>> {
        let key_pair =
            KeyPair::from_pem(private_key_pem).context("Failed to parse private key")?;

        // Use ring for signing
        let pkcs8 = key_pair.serialize_der();
        let ring_key_pair = signature::Ed25519KeyPair::from_pkcs8(&pkcs8)
            .context("Failed to create Ed25519 key pair")?;

        let signature = ring_key_pair.sign(data);
        Ok(signature.as_ref().to_vec())
    }

    /// Verify a signature with a certificate
    pub fn verify_signature(certificate_pem: &str, data: &[u8], signature: &[u8]) -> Result<bool> {
        // Parse the certificate to extract public key
        let pem = pem::parse(certificate_pem).context("Failed to parse PEM")?;
        let cert = x509_parser::parse_x509_certificate(&pem.contents())
            .context("Failed to parse X509 certificate")?
            .1;

        let public_key = cert
            .public_key()
            .subject_public_key
            .data
            .as_ref();

        // Verify using ring
        let peer_public_key = signature::UnparsedPublicKey::new(
            &signature::ED25519,
            public_key,
        );

        match peer_public_key.verify(data, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Derive a unique node ID from a public key (using SHA-256)
    fn derive_node_id(public_key: &[u8]) -> String {
        use ring::digest;
        let digest = digest::digest(&digest::SHA256, public_key);
        hex::encode(&digest.as_ref()[..16]) // Use first 16 bytes
    }

    /// Extract address from certificate
    pub fn extract_address_from_cert(certificate_pem: &str) -> Result<SocketAddr> {
        let pem = pem::parse(certificate_pem).context("Failed to parse PEM")?;
        let cert = x509_parser::parse_x509_certificate(&pem.contents())
            .context("Failed to parse X509 certificate")?
            .1;

        // Extract IP from SAN
        let mut ip_addr = None;
        if let Ok(Some(san)) = cert.subject_alternative_name() {
            for name in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::IPAddress(ip) = name {
                    if ip.len() == 4 {
                        ip_addr = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                            ip[0], ip[1], ip[2], ip[3],
                        )));
                    } else if ip.len() == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(ip);
                        ip_addr = Some(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                    }
                    break;
                }
            }
        }

        let ip = ip_addr.context("No IP address found in certificate")?;

        // Extract port from custom extension
        let mut port = 0u16;
        for ext in cert.extensions() {
            // Check for our custom port extension (OID: 1.3.6.1.4.1.99999.1)
            if ext.oid.to_string() == "1.3.6.1.4.1.99999.1" {
                let port_str = String::from_utf8_lossy(ext.value);
                if let Some(port_value) = port_str.strip_prefix("port:") {
                    port = port_value
                        .parse()
                        .context("Failed to parse port from extension")?;
                }
                break;
            }
        }

        if port == 0 {
            anyhow::bail!("No port found in certificate");
        }

        Ok(SocketAddr::new(ip, port))
    }
}

/// Node certificate with associated metadata
#[derive(Debug, Clone)]
pub struct NodeCertificate {
    pub node_id: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub address: SocketAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_certificate() {
        let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let cert = CertificateManager::generate_node_certificate("test-node", &addr).unwrap();

        assert!(!cert.node_id.is_empty());
        assert!(!cert.certificate_pem.is_empty());
        assert!(!cert.private_key_pem.is_empty());
        assert_eq!(cert.address, addr);
    }

    #[test]
    fn test_sign_and_verify() {
        let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let cert = CertificateManager::generate_node_certificate("test-node", &addr).unwrap();

        let data = b"test data to sign";
        let signature = CertificateManager::sign_data(&cert.private_key_pem, data).unwrap();

        let valid =
            CertificateManager::verify_signature(&cert.certificate_pem, data, &signature).unwrap();
        assert!(valid);

        // Test with wrong data
        let wrong_data = b"wrong data";
        let invalid = CertificateManager::verify_signature(&cert.certificate_pem, wrong_data, &signature)
            .unwrap();
        assert!(!invalid);
    }

    #[test]
    fn test_extract_address() {
        let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let cert = CertificateManager::generate_node_certificate("test-node", &addr).unwrap();

        let extracted = CertificateManager::extract_address_from_cert(&cert.certificate_pem).unwrap();
        assert_eq!(extracted, addr);
    }
}
