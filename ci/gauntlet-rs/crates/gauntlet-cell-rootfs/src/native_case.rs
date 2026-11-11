//! Fixed apparatus cases are separate from Guard qualification roles.
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeCase {
    Success,
    Timeout,
    Cancel,
}

impl NativeCase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Timeout => "timeout",
            Self::Cancel => "cancel",
        }
    }
}

impl std::str::FromStr for NativeCase {
    type Err = String;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "success" => Ok(Self::Success),
            "timeout" => Ok(Self::Timeout),
            "cancel" => Ok(Self::Cancel),
            _ => Err("fixed native apparatus case required".into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NativeApparatusReport {
    pub report: serde_json::Value,
    /// Includes execution/cleanup uncertainty even when a report is retained.
    pub error: Option<String>,
}
