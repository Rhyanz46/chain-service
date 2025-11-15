pub mod distributed;
pub mod node_registry;

pub use distributed::DistributedRegistry;
pub use node_registry::{NodeRegistry, NodeInfo};

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Registry message types for gossip protocol
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegistryMessage {
    /// Announce a new node joining the network
    NodeJoin {
        node_id: String,
        certificate: String,
        address: SocketAddr,
        timestamp: i64,
    },

    /// Update node information
    NodeUpdate {
        node_id: String,
        address: SocketAddr,
        timestamp: i64,
    },

    /// Node leaving the network
    NodeLeave {
        node_id: String,
        timestamp: i64,
    },

    /// Request full node list
    NodeListRequest,

    /// Response with full node list
    NodeListResponse {
        nodes: Vec<NodeInfo>,
    },

    /// Heartbeat to indicate node is still alive
    Heartbeat {
        node_id: String,
        timestamp: i64,
    },
}

/// Registry event for notifications
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum RegistryEvent {
    NodeJoined(NodeInfo),
    NodeLeft(String),
    NodeUpdated(NodeInfo),
}
