//! Versioned Rust MCP dispatch. Root connection/peer custody and shared operation
//! budgets belong to the caller. Protocol success is never a Guard verdict.
mod catalog;
mod session;
#[cfg(unix)]
mod transport;

pub use catalog::CATALOG_SHA256;
use serde_json::Value;
pub use session::Session;
use std::fmt;
#[cfg(unix)]
pub use transport::McpStream;

pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_SESSION_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SESSION_MESSAGES: usize = 1000;
pub const LATEST_PROTOCOL_VERSION: &str = "2025-11-25";
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    LATEST_PROTOCOL_VERSION,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Mail,
    Crm,
    Calendar,
    Docs,
    Tables,
    Chat,
    Tickets,
}
impl Family {
    pub fn name(self) -> &'static str {
        match self {
            Self::Mail => "mail",
            Self::Crm => "crm",
            Self::Calendar => "calendar",
            Self::Docs => "docs",
            Self::Tables => "tables",
            Self::Chat => "chat",
            Self::Tickets => "tickets",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "mail" => Some(Self::Mail),
            "crm" => Some(Self::Crm),
            "calendar" => Some(Self::Calendar),
            "docs" => Some(Self::Docs),
            "tables" => Some(Self::Tables),
            "chat" => Some(Self::Chat),
            "tickets" => Some(Self::Tickets),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum TransportError {
    Catalog,
    Malformed,
    FrameBound,
    SessionBound,
    Closed,
    ResponseBound,
    Io(String),
    Deadline,
    Cancelled,
    Truncated,
}
impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Catalog => "invalid pinned MCP catalog",
            Self::Malformed => "malformed MCP frame",
            Self::FrameBound => "MCP frame exceeds bound",
            Self::SessionBound => "MCP session exceeds bound",
            Self::Closed => "MCP session is closed",
            Self::ResponseBound => "MCP response exceeds bound",
            Self::Io(message) => message,
            Self::Deadline => "MCP transport deadline",
            Self::Cancelled => "MCP transport cancelled",
            Self::Truncated => "MCP stream ended inside a frame",
        })
    }
}
impl std::error::Error for TransportError {}

#[derive(Debug)]
pub struct OperationError {
    pub category: String,
    pub message: String,
}

/// Root callers wrap the backend with their authenticated global budget and
/// observations. A per-session dispatcher must not mint an independent quota.
pub trait Operations {
    fn call(
        &mut self,
        operation: &str,
        original_arguments: &Value,
        request_id: Value,
    ) -> Result<Value, OperationError>;
}
impl Operations for gauntlet_world::World {
    fn call(
        &mut self,
        operation: &str,
        original_arguments: &Value,
        request_id: Value,
    ) -> Result<Value, OperationError> {
        let canonical = gauntlet_contracts::canonicalize(original_arguments.to_string().as_bytes())
            .map_err(|e| OperationError {
                category: "ValueError".into(),
                message: e.to_string(),
            })?;
        let raw = std::str::from_utf8(&canonical).map_err(|e| OperationError {
            category: "ValueError".into(),
            message: e.to_string(),
        })?;
        gauntlet_world::World::call(self, operation, raw, request_id).map_err(|e| OperationError {
            category: e.category().into(),
            message: e.to_string(),
        })
    }
}

pub(crate) fn integer(value: &Value) -> bool {
    value
        .as_number()
        .is_some_and(|v| !v.to_string().contains(['.', 'e', 'E']))
}
