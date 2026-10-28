//! Kernel-only check of the separately declared private-loopback profile.
use crate::{CellError, Result};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

const INVALID: CellError =
    CellError("private network contains an invalid or external interface/address/route");
fn hexadecimal(value: &str) -> Result<u128> {
    if value.is_empty() || value.len() > 32 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(INVALID);
    }
    u128::from_str_radix(value, 16).map_err(|_| INVALID)
}
pub fn validate_private_topology(
    devices: &str,
    routes4: &str,
    routes6: &str,
    addresses6: &str,
) -> Result<Value> {
    if [devices, routes4, routes6, addresses6]
        .iter()
        .any(|s| s.len() > 65536 || !s.is_ascii())
    {
        return Err(INVALID);
    }
    let interfaces: Vec<_> = devices
        .lines()
        .filter_map(|line| line.split_once(':').map(|(name, _)| name.trim()))
        .collect();
    if interfaces != ["lo"] {
        return Err(INVALID);
    }
    for line in routes4.lines().skip(1) {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 11 || f[0] != "lo" || hexadecimal(f[2])? != 0 || hexadecimal(f[7])? == 0 {
            return Err(INVALID);
        }
        let destination = u32::try_from(hexadecimal(f[1])?).map_err(|_| INVALID)?;
        if !Ipv4Addr::from(destination.to_le_bytes()).is_loopback() {
            return Err(INVALID);
        }
    }
    for line in routes6.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 10 || f[9] != "lo" || hexadecimal(f[4])? != 0 {
            return Err(INVALID);
        }
        let destination = hexadecimal(f[0])?;
        let stub = hexadecimal(f[8])? & 0x200 != 0 && destination == 0 && f[1] == "00";
        if !(stub || Ipv6Addr::from(destination).is_loopback() && f[1] == "80") {
            return Err(INVALID);
        }
    }
    for line in addresses6.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 6 || f[5] != "lo" || !Ipv6Addr::from(hexadecimal(f[0])?).is_loopback() {
            return Err(INVALID);
        }
    }
    Ok(
        json!({"schema":"product-cell-network-topology.v1","interfaces":["lo"],
        "ipv4_routes":routes4,"ipv6_routes":routes6,"ipv6_addresses":addresses6}),
    )
}
fn kernel_file(name: &str) -> Result<String> {
    let mut raw = Vec::new();
    File::open(format!("/proc/self/net/{name}"))
        .map_err(|_| INVALID)?
        .take(65537)
        .read_to_end(&mut raw)
        .map_err(|_| INVALID)?;
    if raw.len() > 65536 || !raw.is_ascii() {
        return Err(INVALID);
    }
    String::from_utf8(raw).map_err(|_| INVALID)
}
pub fn observe_private_loopback() -> Result<Value> {
    if !cfg!(target_os = "linux") {
        return Err(INVALID);
    }
    validate_private_topology(
        &kernel_file("dev")?,
        &kernel_file("route")?,
        &kernel_file("ipv6_route")?,
        &kernel_file("if_inet6")?,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_loopback_and_kernel_ipv6_reject_stubs_are_accepted() {
        let devices = "Inter-| Receive\n lo: 0 0\n";
        let stub="00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n";
        assert!(validate_private_topology(
            devices,
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n",
            stub,
            ""
        )
        .is_ok());
        assert!(validate_private_topology("eth0: 0\n", "", "", "").is_err());
        assert!(validate_private_topology(
            devices,
            "header\nlo 00000000 00000000 0001 0 0 0 00000000 0 0 0\n",
            "",
            ""
        )
        .is_err());
        assert!(
            validate_private_topology(devices, "", &stub.replace("00200200", "00000001"), "")
                .is_err()
        );
        assert!(validate_private_topology(
            devices,
            "",
            "",
            "20010db8000000000000000000000001 01 80 00 80 lo\n"
        )
        .is_err());
    }
}
