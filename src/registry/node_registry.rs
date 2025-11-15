use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Information about a node in the network
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub certificate: String,
    pub address: SocketAddr,
    pub last_seen: i64,
    pub joined_at: i64,
}

#[allow(dead_code)]
impl NodeInfo {
    pub fn new(node_id: String, certificate: String, address: SocketAddr) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        Self {
            node_id,
            certificate,
            address,
            last_seen: now,
            joined_at: now,
        }
    }

    pub fn update_last_seen(&mut self) {
        self.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
    }

    pub fn is_stale(&self, timeout_seconds: i64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        (now - self.last_seen) > timeout_seconds
    }
}

/// Node registry for tracking all nodes in the network
pub struct NodeRegistry {
    nodes: Arc<RwLock<HashMap<String, NodeInfo>>>,
    stale_timeout_seconds: i64,
}

#[allow(dead_code)]
impl NodeRegistry {
    /// Create a new node registry
    pub fn new(stale_timeout_seconds: i64) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            stale_timeout_seconds,
        }
    }

    /// Register a new node
    pub fn register_node(&self, node_info: NodeInfo) -> Result<()> {
        let mut nodes = self
            .nodes
            .write()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        nodes.insert(node_info.node_id.clone(), node_info);
        Ok(())
    }

    /// Update a node's information
    pub fn update_node(&self, node_id: &str, address: SocketAddr) -> Result<bool> {
        let mut nodes = self
            .nodes
            .write()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        if let Some(node) = nodes.get_mut(node_id) {
            node.address = address;
            node.update_last_seen();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Update node's last seen timestamp
    pub fn update_last_seen(&self, node_id: &str) -> Result<bool> {
        let mut nodes = self
            .nodes
            .write()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        if let Some(node) = nodes.get_mut(node_id) {
            node.update_last_seen();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Unregister a node
    pub fn unregister_node(&self, node_id: &str) -> Result<Option<NodeInfo>> {
        let mut nodes = self
            .nodes
            .write()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        Ok(nodes.remove(node_id))
    }

    /// Get a node by ID
    pub fn get_node(&self, node_id: &str) -> Result<Option<NodeInfo>> {
        let nodes = self
            .nodes
            .read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        Ok(nodes.get(node_id).cloned())
    }

    /// Get all nodes
    pub fn get_all_nodes(&self) -> Result<Vec<NodeInfo>> {
        let nodes = self
            .nodes
            .read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        Ok(nodes.values().cloned().collect())
    }

    /// Get all active nodes (non-stale)
    pub fn get_active_nodes(&self) -> Result<Vec<NodeInfo>> {
        let nodes = self
            .nodes
            .read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        Ok(nodes
            .values()
            .filter(|node| !node.is_stale(self.stale_timeout_seconds))
            .cloned()
            .collect())
    }

    /// Remove stale nodes
    pub fn remove_stale_nodes(&self) -> Result<Vec<String>> {
        let mut nodes = self
            .nodes
            .write()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        let stale_node_ids: Vec<String> = nodes
            .values()
            .filter(|node| node.is_stale(self.stale_timeout_seconds))
            .map(|node| node.node_id.clone())
            .collect();

        for node_id in &stale_node_ids {
            nodes.remove(node_id);
        }

        Ok(stale_node_ids)
    }

    /// Get node count
    pub fn node_count(&self) -> Result<usize> {
        let nodes = self
            .nodes
            .read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        Ok(nodes.len())
    }

    /// Check if a node exists
    pub fn has_node(&self, node_id: &str) -> Result<bool> {
        let nodes = self
            .nodes
            .read()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        Ok(nodes.contains_key(node_id))
    }

    /// Clear all nodes
    pub fn clear(&self) -> Result<()> {
        let mut nodes = self
            .nodes
            .write()
            .map_err(|e| anyhow::anyhow!("Lock poisoned: {}", e))?;

        nodes.clear();
        Ok(())
    }
}

impl Clone for NodeRegistry {
    fn clone(&self) -> Self {
        Self {
            nodes: Arc::clone(&self.nodes),
            stale_timeout_seconds: self.stale_timeout_seconds,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_registry() {
        let registry = NodeRegistry::new(300);
        let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let node = NodeInfo::new("node1".to_string(), "cert1".to_string(), addr);

        registry.register_node(node.clone()).unwrap();
        assert_eq!(registry.node_count().unwrap(), 1);

        let retrieved = registry.get_node("node1").unwrap().unwrap();
        assert_eq!(retrieved.node_id, "node1");

        registry.unregister_node("node1").unwrap();
        assert_eq!(registry.node_count().unwrap(), 0);
    }
}
