use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tracing::{debug, error, info, warn};
use crate::network::id_manager::{NodeAssignment, IdReservation};

/// Database untuk menyimpan network state secara persistent
#[derive(Debug)]
pub struct NetworkDatabase {
    /// Path ke database file
    db_path: PathBuf,
    /// In-memory cache
    cache: NetworkState,
    /// Auto-save interval (detik)
    auto_save_interval: u64,
}

/// Network state yang akan disimpan ke database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkState {
    /// Node assignments
    pub assignments: HashMap<String, NodeAssignment>,
    /// Active reservations
    pub reservations: HashMap<String, IdReservation>,
    /// Network metadata
    pub metadata: NetworkMetadata,
}

/// Network metadata untuk tracking info general
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetadata {
    /// Network creation time
    pub created_at: u64,
    /// Last update time
    pub last_updated: u64,
    /// Total nodes that have ever joined
    pub total_nodes_joined: u64,
    /// Network version
    pub version: String,
    /// First node ID (bootstrap node)
    pub bootstrap_node: Option<String>,
}

impl NetworkDatabase {
    /// Create new NetworkDatabase dengan path tertentu
    pub async fn new(db_path: PathBuf) -> Result<Self> {
        let db = Self {
            auto_save_interval: 60, // Auto-save tiap 60 detik
            db_path: db_path.clone(),
            cache: Self::load_or_create_state(&db_path).await?,
        };

        info!("NetworkDatabase initialized at {}", db_path.display());
        Ok(db)
    }

    /// Load existing state atau create baru
    async fn load_or_create_state(db_path: &PathBuf) -> Result<NetworkState> {
        if db_path.exists() {
            debug!("Loading existing network state from {}", db_path.display());
            Self::load_state(db_path).await
        } else {
            info!("Creating new network state at {}", db_path.display());
            let state = NetworkState {
                assignments: HashMap::new(),
                reservations: HashMap::new(),
                metadata: NetworkMetadata {
                    created_at: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    last_updated: 0,
                    total_nodes_joined: 0,
                    version: "1.0.0".to_string(),
                    bootstrap_node: None,
                },
            };

            // Save initial state
            if let Some(parent) = db_path.parent() {
                fs::create_dir_all(parent).await?;
            }

            // Simpan state baru
            let content = serde_json::to_string_pretty(&state)?;
            fs::write(db_path, content).await?;

            Ok(state)
        }
    }

    /// Load state dari file
    async fn load_state(db_path: &PathBuf) -> Result<NetworkState> {
        let mut file = fs::File::open(db_path).await?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).await?;

        let state: NetworkState = serde_json::from_str(&contents)
            .map_err(|e| anyhow!("Failed to parse network state: {}", e))?;

        info!("Loaded network state: {} assignments, {} reservations",
              state.assignments.len(), state.reservations.len());

        Ok(state)
    }

    /// Save state ke file
    pub async fn save_state(&self) -> Result<()> {
        debug!("Saving network state to {}", self.db_path.display());

        let mut state = self.cache.clone();

        // Update metadata
        state.metadata.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create backup
        if self.db_path.exists() {
            let backup_path = self.db_path.with_extension("bak");
            if let Err(e) = fs::copy(&self.db_path, &backup_path).await {
                warn!("Failed to create backup: {}", e);
            }
        }

        // Serialize dan save
        let content = serde_json::to_string_pretty(&state)?;

        // Write to temporary file first (atomic operation)
        let temp_path = self.db_path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path).await?;
        file.write_all(content.as_bytes()).await?;
        file.sync_all().await?;

        // Rename to final path
        fs::rename(&temp_path, &self.db_path).await?;

        debug!("Network state saved successfully");
        Ok(())
    }

    /// Add new node assignment
    pub async fn add_assignment(&mut self, assignment: NodeAssignment) -> Result<()> {
        debug!("Adding assignment: {} -> {}", assignment.node_id, assignment.ip_address);

        // Update cache
        self.cache.assignments.insert(assignment.node_id.clone(), assignment.clone());

        // Update metadata
        self.cache.metadata.total_nodes_joined += 1;

        // Set bootstrap node if this is the first node
        if self.cache.metadata.bootstrap_node.is_none() {
            self.cache.metadata.bootstrap_node = Some(assignment.node_id.clone());
            info!("Set bootstrap node: {}", assignment.node_id);
        }

        // Save to disk
        self.save_state().await?;

        info!("Assignment saved: {} -> {}", assignment.node_id, assignment.ip_address);
        Ok(())
    }

    /// Remove node assignment
    pub async fn remove_assignment(&mut self, node_id: &str) -> Result<NodeAssignment> {
        debug!("Removing assignment: {}", node_id);

        let assignment = self.cache.assignments.remove(node_id)
            .ok_or_else(|| anyhow!("Assignment not found: {}", node_id))?;

        // Save to disk
        self.save_state().await?;

        info!("Assignment removed: {} -> {}", node_id, assignment.ip_address);
        Ok(assignment)
    }

    /// Update assignment
    pub async fn update_assignment(&mut self, node_id: &str, assignment: NodeAssignment) -> Result<()> {
        debug!("Updating assignment: {}", node_id);

        if !self.cache.assignments.contains_key(node_id) {
            return Err(anyhow!("Assignment not found: {}", node_id));
        }

        self.cache.assignments.insert(node_id.to_string(), assignment);
        self.save_state().await?;

        info!("Assignment updated: {}", node_id);
        Ok(())
    }

    /// Get assignment by node ID
    pub async fn get_assignment(&self, node_id: &str) -> Option<NodeAssignment> {
        self.cache.assignments.get(node_id).cloned()
    }

    /// Get all assignments
    pub async fn get_all_assignments(&self) -> HashMap<String, NodeAssignment> {
        self.cache.assignments.clone()
    }

    /// Add reservation
    pub async fn add_reservation(&mut self, ip: String, reservation: IdReservation) -> Result<()> {
        debug!("Adding reservation: {} -> {}", ip, reservation.reserved_id);

        self.cache.reservations.insert(ip, reservation.clone());
        self.save_state().await?;

        info!("Reservation added: {} -> {}", reservation.reserved_id, reservation.reserved_by);
        Ok(())
    }

    /// Remove reservation
    pub async fn remove_reservation(&mut self, ip: &str) -> Result<Option<IdReservation>> {
        debug!("Removing reservation: {}", ip);

        let reservation = self.cache.reservations.remove(ip);

        if let Some(ref res) = reservation {
            self.save_state().await?;
            info!("Reservation removed: {} -> {}", res.reserved_id, ip);
        }

        Ok(reservation)
    }

    /// Get all reservations
    pub async fn get_all_reservations(&self) -> HashMap<String, IdReservation> {
        self.cache.reservations.clone()
    }

    /// Get network metadata
    pub async fn get_metadata(&self) -> NetworkMetadata {
        self.cache.metadata.clone()
    }

    /// Check if network is empty (no active assignments)
    pub async fn is_empty(&self) -> bool {
        self.cache.assignments.is_empty()
    }

    /// Get total nodes count
    pub async fn get_node_count(&self) -> usize {
        self.cache.assignments.len()
    }

    /// Cleanup expired reservations
    pub async fn cleanup_expired_reservations(&mut self, timeout_seconds: u64) -> Result<usize> {
        debug!("Cleaning up expired reservations (timeout: {}s)", timeout_seconds);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut removed_count = 0;
        let mut to_remove = Vec::new();

        for (ip, reservation) in self.cache.reservations.iter() {
            if now > reservation.expires_at {
                to_remove.push(ip.clone());
            }
        }

        for ip in to_remove {
            if let Some(reservation) = self.cache.reservations.remove(&ip) {
                warn!("Expired reservation removed: {} ({}s ago)",
                      reservation.reserved_id, now - reservation.reserved_at);
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            self.save_state().await?;
            info!("Cleaned up {} expired reservations", removed_count);
        }

        Ok(removed_count)
    }

    /// Cleanup stale nodes (offline > threshold)
    pub async fn cleanup_stale_nodes(&mut self, offline_threshold_seconds: u64) -> Result<usize> {
        debug!("Cleaning up stale nodes (threshold: {}s)", offline_threshold_seconds);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut removed_count = 0;
        let mut to_remove = Vec::new();

        for (node_id, assignment) in self.cache.assignments.iter() {
            let offline_duration = now - assignment.last_seen;
            if offline_duration > offline_threshold_seconds {
                to_remove.push(node_id.clone());
            }
        }

        for node_id in to_remove {
            if let Some(assignment) = self.cache.assignments.remove(&node_id) {
                warn!("Stale node removed: {} (offline for {}s)",
                      node_id, now - assignment.last_seen);
                removed_count += 1;
            }
        }

        if removed_count > 0 {
            self.save_state().await?;
            info!("Cleaned up {} stale nodes", removed_count);
        }

        Ok(removed_count)
    }

    /// Force save state
    pub async fn force_save(&self) -> Result<()> {
        self.save_state().await
    }

    /// Get database statistics
    pub async fn get_stats(&self) -> DatabaseStats {
        DatabaseStats {
            total_assignments: self.cache.assignments.len(),
            total_reservations: self.cache.reservations.len(),
            total_nodes_joined: self.cache.metadata.total_nodes_joined,
            network_age_seconds: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() - self.cache.metadata.created_at,
            last_updated: self.cache.metadata.last_updated,
            bootstrap_node: self.cache.metadata.bootstrap_node.clone(),
        }
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub total_assignments: usize,
    pub total_reservations: usize,
    pub total_nodes_joined: u64,
    pub network_age_seconds: u64,
    pub last_updated: u64,
    pub bootstrap_node: Option<String>,
}