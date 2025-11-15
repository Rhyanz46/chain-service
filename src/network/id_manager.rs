use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

/// Network ID Manager untuk alokasi dan management node IDs
#[derive(Debug)]
pub struct NetworkIdManager {
    /// Available IDs yang bisa dipilih oleh node pertama
    available_ids: RwLock<HashMap<String, IdInfo>>,
    /// Current ID assignments (node_id -> NodeAssignment)
    assignments: RwLock<HashMap<String, NodeAssignment>>,
    /// ID reservations yang sedang ditunggu konfirmasi
    reservations: RwLock<HashMap<String, IdReservation>>,
    /// Network settings
    settings: NetworkSettings,
}

/// Informasi tentang ID yang tersedia
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdInfo {
    pub description: String,
    pub reserved: bool,
    pub network_type: String,
}

/// Assignment informasi untuk node yang sudah terdaftar
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeAssignment {
    pub node_id: String,
    pub ip_address: SocketAddr,
    pub assigned_at: u64,
    pub last_seen: u64,
    pub certificate_fingerprint: String,
    pub network_type: String,
}

/// ID reservation untuk node yang mau join
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdReservation {
    pub reserved_id: String,
    pub reserved_by: SocketAddr,
    pub reserved_at: u64,
    pub expires_at: u64,
    pub network_type: String,
}

/// Network settings dari config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    pub min_id_length: usize,
    pub max_id_length: usize,
    pub id_format_regex: Option<String>,
    pub max_nodes_per_network: HashMap<String, u32>,
    pub id_reservation_timeout: u64,
}

impl NetworkIdManager {
    /// Create new NetworkIdManager dengan load dari file config
    pub async fn new() -> Result<Self> {
        let settings = Self::load_settings().await?;
        let available_ids = Self::load_available_ids().await?;

        info!("Loaded {} available IDs", available_ids.len());

        Ok(Self {
            available_ids: RwLock::new(available_ids),
            assignments: RwLock::new(HashMap::new()),
            reservations: RwLock::new(HashMap::new()),
            settings,
        })
    }

    /// Assign ID untuk node pertama (first-node scenario)
    pub async fn assign_first_node_id(&self, ip_address: SocketAddr, requested_id: &str) -> Result<String> {
        debug!("First node requesting ID: {}", requested_id);

        // Check if requested ID is available in predefined list
        let mut available = self.available_ids.write().await;
        if let Some(id_info) = available.get(requested_id) {
            if id_info.reserved {
                return Err(anyhow!("Requested ID {} is reserved", requested_id));
            }
        } else {
            return Err(anyhow!("Requested ID {} is not in predefined list", requested_id));
        }

        // Check network capacity
        let assignments = self.assignments.read().await;
        let network_type = self.extract_network_type(requested_id);
        let current_count = assignments.values()
            .filter(|assignment| assignment.network_type == network_type)
            .count();

        let max_capacity = self.settings.max_nodes_per_network
            .get(&network_type)
            .unwrap_or(&999); // Default to 999 if not specified

        if current_count >= *max_capacity as usize {
            return Err(anyhow!("Network {} is at full capacity ({} nodes)",
                              network_type, max_capacity));
        }

        drop(assignments);

        // Assign the ID
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let assignment = NodeAssignment {
            node_id: requested_id.to_string(),
            ip_address,
            assigned_at: now,
            last_seen: now,
            certificate_fingerprint: String::new(), // Will be filled later
            network_type: network_type.clone(),
        };

        // Mark ID as used
        available.remove(requested_id);

        // Store assignment
        let mut assignments = self.assignments.write().await;
        assignments.insert(requested_id.to_string(), assignment);

        info!("First node assigned ID: {} to {}", requested_id, ip_address);
        Ok(requested_id.to_string())
    }

    /// Reserve ID untuk node baru yang mau join
    pub async fn reserve_id(&self, ip_address: SocketAddr, network_type: &str) -> Result<String> {
        debug!("Node {} requesting ID reservation for network {}", ip_address, network_type);

        let available = self.available_ids.read().await;
        let assignments = self.assignments.read().await;

        // Find available ID for this network type
        let available_id = available
            .iter()
            .find(|(id, info)| {
                !info.reserved
                && self.extract_network_type(id) == network_type
                && !assignments.contains_key(*id)
            })
            .map(|(id, _)| id.clone());

        if let Some(reserved_id) = available_id {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let reservation = IdReservation {
                reserved_id: reserved_id.clone(),
                reserved_by: ip_address,
                reserved_at: now,
                expires_at: now + self.settings.id_reservation_timeout,
                network_type: network_type.to_string(),
            };

            let mut reservations = self.reservations.write().await;
            reservations.insert(ip_address.to_string(), reservation);

            info!("Reserved ID {} for {} (expires in {}s)",
                  reserved_id, ip_address, self.settings.id_reservation_timeout);
            Ok(reserved_id)
        } else {
            Err(anyhow!("No available IDs in network {}", network_type))
        }
    }

    /// Confirm ID reservation dan assign ke node
    pub async fn confirm_assignment(
        &self,
        ip_address: SocketAddr,
        certificate_fingerprint: &str
    ) -> Result<String> {
        debug!("Confirming assignment for {} with fingerprint {}",
               ip_address, certificate_fingerprint);

        // Check if there's a reservation
        let mut reservations = self.reservations.write().await;
        let reservation = reservations.remove(&ip_address.to_string())
            .ok_or_else(|| anyhow!("No reservation found for {}", ip_address))?;

        // Check if reservation expired
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if now > reservation.expires_at {
            return Err(anyhow!("Reservation expired for {}", ip_address));
        }

        // Create final assignment
        let assignment = NodeAssignment {
            node_id: reservation.reserved_id.clone(),
            ip_address,
            assigned_at: reservation.reserved_at,
            last_seen: now,
            certificate_fingerprint: certificate_fingerprint.to_string(),
            network_type: reservation.network_type.clone(),
        };

        // Remove from available IDs
        let mut available = self.available_ids.write().await;
        available.remove(&reservation.reserved_id);

        // Store assignment
        let mut assignments = self.assignments.write().await;
        assignments.insert(reservation.reserved_id.clone(), assignment);

        info!("Confirmed assignment: {} -> {}",
              reservation.reserved_id, ip_address);
        Ok(reservation.reserved_id)
    }

    /// Check if IP sudah ada assignment dan bisa reclaim ID lama
    pub async fn check_ip_reclamation(&self, ip_address: SocketAddr) -> Option<String> {
        debug!("Checking IP reclamation for {}", ip_address);

        let assignments = self.assignments.read().await;

        // Cari assignment dengan IP yang sama
        for (node_id, assignment) in assignments.iter() {
            if assignment.ip_address == ip_address {
                // Check if node has been offline for > 24 hours
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let offline_duration = now - assignment.last_seen;
                let one_day = 24 * 60 * 60;

                if offline_duration >= one_day {
                    info!("Found reclaimable ID: {} for {} (offline for {}s)",
                          node_id, ip_address, offline_duration);
                    return Some(node_id.clone());
                }
            }
        }

        None
    }

    /// Update last seen untuk node
    pub async fn update_last_seen(&self, node_id: &str) -> Result<()> {
        debug!("Updating last seen for {}", node_id);

        let mut assignments = self.assignments.write().await;
        if let Some(assignment) = assignments.get_mut(node_id) {
            assignment.last_seen = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Ok(())
        } else {
            Err(anyhow!("Node {} not found", node_id))
        }
    }

    /// Clean up expired reservations
    pub async fn cleanup_expired_reservations(&self) -> usize {
        debug!("Cleaning up expired reservations");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut reservations = self.reservations.write().await;
        let initial_count = reservations.len();

        reservations.retain(|ip, reservation| {
            if now > reservation.expires_at {
                warn!("Reservation expired for {} (ID: {})", ip, reservation.reserved_id);
                false
            } else {
                true
            }
        });

        let cleaned_count = initial_count - reservations.len();
        if cleaned_count > 0 {
            info!("Cleaned up {} expired reservations", cleaned_count);
        }

        cleaned_count
    }

    /// Remove nodes yang offline > 24 jam
    pub async fn cleanup_stale_nodes(&self) -> usize {
        debug!("Cleaning up stale nodes");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let one_day = 24 * 60 * 60;

        let mut assignments = self.assignments.write().await;
        let initial_count = assignments.len();

        let mut to_remove = Vec::new();
        for (node_id, assignment) in assignments.iter() {
            if now - assignment.last_seen > one_day {
                to_remove.push(node_id.clone());
            }
        }

        for node_id in to_remove {
            if let Some(assignment) = assignments.remove(&node_id) {
                // Return ID to available pool
                let mut available = self.available_ids.write().await;
                available.insert(node_id.clone(), IdInfo {
                    description: format!("Previously used by {}", assignment.ip_address),
                    reserved: false,
                    network_type: assignment.network_type.clone(),
                });

                warn!("Removed stale node: {} ({})", node_id, assignment.ip_address);
            }
        }

        let removed_count = initial_count - assignments.len();
        if removed_count > 0 {
            info!("Removed {} stale nodes", removed_count);
        }

        removed_count
    }

    /// Get semua current assignments
    pub async fn get_all_assignments(&self) -> HashMap<String, NodeAssignment> {
        self.assignments.read().await.clone()
    }

    /// Get available IDs untuk network type tertentu
    pub async fn get_available_ids(&self, network_type: &str) -> Vec<String> {
        let available = self.available_ids.read().await;
        let assignments = self.assignments.read().await;

        available
            .iter()
            .filter(|(id, info)| {
                !info.reserved
                && self.extract_network_type(id) == network_type
                && !assignments.contains_key(*id)
            })
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Extract network type dari node ID
    pub fn extract_network_type(&self, node_id: &str) -> String {
        if let Some(hyphen_pos) = node_id.find('-') {
            node_id[..hyphen_pos].to_string()
        } else {
            "Unknown".to_string()
        }
    }

    /// Load network settings
    async fn load_settings() -> Result<NetworkSettings> {
        // Default settings
        Ok(NetworkSettings {
            min_id_length: 8,
            max_id_length: 32,
            id_format_regex: Some("^[A-Za-z0-9_-]+$".to_string()),
            max_nodes_per_network: {
                let mut map = HashMap::new();
                map.insert("MainNet".to_string(), 999);
                map.insert("TestNet".to_string(), 99);
                map.insert("DevNet".to_string(), 49);
                map.insert("CustomNet".to_string(), 99);
                map
            },
            id_reservation_timeout: 300, // 5 menit
        })
    }

    /// Load available IDs dari config file
    async fn load_available_ids() -> Result<HashMap<String, IdInfo>> {
        // Untuk sekarang, hardcode dari config/network_ids.toml
        // Nanti bisa dibaca dari file untuk flexibility

        let mut available = HashMap::new();

        // Main Network IDs
        available.insert("MainNet-001".to_string(), IdInfo {
            description: "Main network primary node".to_string(),
            reserved: false,
            network_type: "MainNet".to_string(),
        });
        available.insert("MainNet-002".to_string(), IdInfo {
            description: "Main network secondary node".to_string(),
            reserved: false,
            network_type: "MainNet".to_string(),
        });
        available.insert("MainNet-003".to_string(), IdInfo {
            description: "Main network tertiary node".to_string(),
            reserved: false,
            network_type: "MainNet".to_string(),
        });

        // Test Network IDs
        available.insert("TestNet-001".to_string(), IdInfo {
            description: "Test network node 1".to_string(),
            reserved: false,
            network_type: "TestNet".to_string(),
        });
        available.insert("TestNet-002".to_string(), IdInfo {
            description: "Test network node 2".to_string(),
            reserved: false,
            network_type: "TestNet".to_string(),
        });

        // Dev Network IDs
        available.insert("DevNet-001".to_string(), IdInfo {
            description: "Development network node 1".to_string(),
            reserved: false,
            network_type: "DevNet".to_string(),
        });

        // Special Purpose IDs
        available.insert("Bootstrap-001".to_string(), IdInfo {
            description: "Bootstrap seed node".to_string(),
            reserved: false,
            network_type: "Bootstrap".to_string(),
        });

        Ok(available)
    }
}