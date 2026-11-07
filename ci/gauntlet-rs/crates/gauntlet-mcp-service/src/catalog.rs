use crate::{Family, TransportError};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const CATALOG_SHA256: &str = "22df4f3850d6d22ef30b6ec45108cde9b4306879c06c99ccce6f3bf53097cafe";
const RAW: &[u8] = include_bytes!("../catalog-python-mcp-1.30.0.v1.json");

pub(crate) struct Catalog {
    pub tools: Vec<Value>,
    validators: BTreeMap<String, jsonschema::Validator>,
}
impl Catalog {
    pub fn load(family: Family) -> Result<Self, TransportError> {
        if format!("{:x}", Sha256::digest(RAW)) != CATALOG_SHA256 {
            return Err(TransportError::Catalog);
        }
        let canonical =
            gauntlet_contracts::canonicalize(RAW).map_err(|_| TransportError::Catalog)?;
        let value: Value =
            serde_json::from_slice(&canonical).map_err(|_| TransportError::Catalog)?;
        if value["mcp_version"] != "1.30.0"
            || value["source_sha256"]
                != "f6e004a65f60a38322e02fc229d4430279fad5db2dc35453eca4f3afefa9086b"
        {
            return Err(TransportError::Catalog);
        }
        let tools = value["families"][family.name()]
            .as_array()
            .ok_or(TransportError::Catalog)?
            .clone();
        let mut validators = BTreeMap::new();
        for tool in &tools {
            let name = tool["name"].as_str().ok_or(TransportError::Catalog)?;
            if !name.starts_with(&format!("{}.", family.name())) {
                return Err(TransportError::Catalog);
            }
            let validator = jsonschema::validator_for(&tool["inputSchema"])
                .map_err(|_| TransportError::Catalog)?;
            if validators.insert(name.to_owned(), validator).is_some() {
                return Err(TransportError::Catalog);
            }
        }
        Ok(Self { tools, validators })
    }
    pub fn validate(&self, name: &str, arguments: &Value) -> Result<(), &'static str> {
        let validator = self.validators.get(name).ok_or("unknown tool")?;
        if !arguments.is_object() {
            return Err("arguments must be an object");
        }
        // JSON Schema's integer includes 1.0; the pinned Python StrictInt does
        // not. These are the only strict integer parameters in the base catalog.
        for field in ["limit", "expected_version"] {
            if arguments.get(field).is_some_and(|v| !crate::integer(v)) {
                return Err("integer parameter requires an integer literal");
            }
        }
        if !validator.is_valid(arguments) {
            return Err("tool arguments do not match the advertised schema");
        }
        Ok(())
    }
}
