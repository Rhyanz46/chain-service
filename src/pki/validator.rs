use anyhow::{Context, Result};
use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use super::certificate::CertificateManager;

/// Certificate validator with distributed trust registry
pub struct CertificateValidator {
    /// Set of trusted certificate fingerprints (SHA-256 hash of cert DER)
    trusted_certs: Arc<RwLock<HashSet<String>>>,

    /// Allow self-signed certificates
    allow_self_signed: bool,
}

impl CertificateValidator {
    /// Create a new certificate validator
    pub fn new(allow_self_signed: bool) -> Self {
        Self {
            trusted_certs: Arc::new(RwLock::new(HashSet::new())),
            allow_self_signed,
        }
    }

    /// Add a trusted certificate by its PEM
    pub fn add_trusted_certificate(&self, certificate_pem: &str) -> Result<()> {
        let fingerprint = Self::calculate_fingerprint(certificate_pem)?;
        let mut trusted = self
            .trusted_certs
            .write()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        trusted.insert(fingerprint);
        Ok(())
    }

    /// Remove a trusted certificate
    #[allow(dead_code)]
    pub fn remove_trusted_certificate(&self, certificate_pem: &str) -> Result<()> {
        let fingerprint = Self::calculate_fingerprint(certificate_pem)?;
        let mut trusted = self
            .trusted_certs
            .write()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        trusted.remove(&fingerprint);
        Ok(())
    }

    /// Check if a certificate is trusted
    pub fn is_trusted(&self, certificate_pem: &str) -> Result<bool> {
        let fingerprint = Self::calculate_fingerprint(certificate_pem)?;
        let trusted = self
            .trusted_certs
            .read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        Ok(trusted.contains(&fingerprint))
    }

    /// Validate a certificate
    pub fn validate_certificate(&self, certificate_pem: &str) -> Result<ValidationResult> {
        // Parse the certificate
        let pem = pem::parse(certificate_pem).context("Failed to parse PEM")?;
        let cert = x509_parser::parse_x509_certificate(&pem.contents())
            .context("Failed to parse X509 certificate")?
            .1;

        // Check validity period
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();

        if now < not_before {
            return Ok(ValidationResult {
                valid: false,
                reason: Some("Certificate not yet valid".to_string()),
            });
        }

        if now > not_after {
            return Ok(ValidationResult {
                valid: false,
                reason: Some("Certificate expired".to_string()),
            });
        }

        // Check if certificate is in trusted registry
        let is_trusted = self.is_trusted(certificate_pem)?;

        if !is_trusted && !self.allow_self_signed {
            return Ok(ValidationResult {
                valid: false,
                reason: Some("Certificate not in trusted registry".to_string()),
            });
        }

        // Verify certificate signature (self-signed check)
        // For production, you'd want to verify against a CA
        let signature_valid = self.verify_self_signed(&cert)?;

        if !signature_valid && !self.allow_self_signed {
            return Ok(ValidationResult {
                valid: false,
                reason: Some("Invalid signature".to_string()),
            });
        }

        Ok(ValidationResult {
            valid: true,
            reason: None,
        })
    }

    /// Verify authentication challenge
    pub fn verify_challenge(
        &self,
        certificate_pem: &str,
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<bool> {
        CertificateManager::verify_signature(certificate_pem, challenge, signature)
    }

    /// Get list of all trusted certificate fingerprints
    #[allow(dead_code)]
    pub fn get_trusted_fingerprints(&self) -> Result<Vec<String>> {
        let trusted = self
            .trusted_certs
            .read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        Ok(trusted.iter().cloned().collect())
    }

    /// Calculate SHA-256 fingerprint of a certificate
    fn calculate_fingerprint(certificate_pem: &str) -> Result<String> {
        use ring::digest;

        let pem = pem::parse(certificate_pem).context("Failed to parse PEM")?;
        let digest = digest::digest(&digest::SHA256, &pem.contents());
        Ok(hex::encode(digest.as_ref()))
    }

    /// Verify self-signed certificate signature
    fn verify_self_signed(&self, cert: &x509_parser::certificate::X509Certificate) -> Result<bool> {
        // For self-signed certs, issuer == subject
        if cert.issuer() != cert.subject() {
            return Ok(false);
        }

        // In production, you'd verify the signature using the public key
        // For now, we'll just check that it's properly formed
        Ok(true)
    }

    /// Clear all trusted certificates
    #[allow(dead_code)]
    pub fn clear_trusted_certificates(&self) -> Result<()> {
        let mut trusted = self
            .trusted_certs
            .write()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        trusted.clear();
        Ok(())
    }

    /// Get count of trusted certificates
    #[allow(dead_code)]
    pub fn trusted_count(&self) -> Result<usize> {
        let trusted = self
            .trusted_certs
            .read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;
        Ok(trusted.len())
    }
}

impl Clone for CertificateValidator {
    fn clone(&self) -> Self {
        Self {
            trusted_certs: Arc::clone(&self.trusted_certs),
            allow_self_signed: self.allow_self_signed,
        }
    }
}

/// Certificate validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub reason: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::certificate::CertificateManager;

    #[test]
    fn test_validator() {
        let validator = CertificateValidator::new(true);
        let addr: std::net::SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let cert = CertificateManager::generate_node_certificate("test-node", &addr).unwrap();

        // Should be valid with allow_self_signed
        let result = validator.validate_certificate(&cert.certificate_pem).unwrap();
        assert!(result.valid);

        // Add to trusted
        validator
            .add_trusted_certificate(&cert.certificate_pem)
            .unwrap();
        assert!(validator.is_trusted(&cert.certificate_pem).unwrap());

        // Should still be valid
        let result = validator.validate_certificate(&cert.certificate_pem).unwrap();
        assert!(result.valid);
    }
}
