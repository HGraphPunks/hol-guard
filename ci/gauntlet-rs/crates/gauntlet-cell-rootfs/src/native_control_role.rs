//! Closed deterministic control roles. These select controller-owned fixtures,
//! never executable text, filesystem paths, approval state or qualification.
use crate::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeControlRole {
    Success,
    InputBinding,
    Injection,
    Boundary,
    Timeout,
    Cancel,
}
impl NativeControlRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::InputBinding => "input-binding",
            Self::Injection => "injection",
            Self::Boundary => "boundary",
            Self::Timeout => "timeout",
            Self::Cancel => "cancel",
        }
    }
    pub fn lifecycle(self) -> bool {
        matches!(self, Self::Timeout | Self::Cancel)
    }
}
impl std::str::FromStr for NativeControlRole {
    type Err = String;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "success" => Ok(Self::Success),
            "input-binding" => Ok(Self::InputBinding),
            "injection" => Ok(Self::Injection),
            "boundary" => Ok(Self::Boundary),
            "timeout" => Ok(Self::Timeout),
            "cancel" => Ok(Self::Cancel),
            _ => Err("closed Native deterministic control role required".into()),
        }
    }
}
