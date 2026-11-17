//! The same hash-pinned libseccomp ABI as the existing Python floor. Loading
//! and installing are confined to the already unprivileged product process.
use crate::root_input::read_root_input;
use crate::seccomp::{action, comparison, ALLOW, ERRNO};
use crate::{
    observe_private_loopback, CellError, NetworkProfile, Result, LIBRARY_SHA256, PROFILE_SHA256,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ffi::{c_void, CStr, CString};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::Path;

const INVALID: CellError = CellError("pinned native libseccomp installation failed");
#[repr(C)]
#[derive(Clone, Copy)]
struct Comparison {
    arg: u32,
    op: i32,
    datum_a: u64,
    datum_b: u64,
}
const _: () = assert!(std::mem::size_of::<Comparison>() == 24);
struct Api {
    handle: *mut c_void,
    _file: File,
    init: unsafe extern "C" fn(u32) -> *mut c_void,
    release: unsafe extern "C" fn(*mut c_void),
    arch_add: unsafe extern "C" fn(*mut c_void, u32) -> i32,
    arch_native: unsafe extern "C" fn() -> u32,
    syscall: unsafe extern "C" fn(*const libc::c_char) -> i32,
    rule_add: unsafe extern "C" fn(*mut c_void, u32, i32, u32, *const Comparison) -> i32,
    load: unsafe extern "C" fn(*mut c_void) -> i32,
}
impl Drop for Api {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.handle);
        }
    }
}

struct LibraryHandle(*mut c_void);
impl Drop for LibraryHandle {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.0);
        }
    }
}
unsafe fn symbol<T: Copy>(handle: *mut c_void, name: &CStr) -> Result<T> {
    if std::mem::size_of::<T>() != std::mem::size_of::<*mut c_void>() {
        return Err(INVALID);
    }
    let pointer = libc::dlsym(handle, name.as_ptr());
    if pointer.is_null() {
        return Err(INVALID);
    }
    // Each T below is the exact public C function signature already used by
    // product_vm_seccomp.py. The complete loaded ELF has an outside fixed hash.
    Ok(std::mem::transmute_copy(&pointer))
}
impl Api {
    fn open() -> Result<Self> {
        let input = read_root_input(
            Path::new("/usr/lib/aarch64-linux-gnu/libseccomp.so.2.5.5"),
            8 * 1024 * 1024,
        )?
        .ok_or(INVALID)?;
        if format!("{:x}", Sha256::digest(&input.bytes)) != LIBRARY_SHA256 {
            return Err(INVALID);
        }
        let path = CString::new(format!("/proc/self/fd/{}", input.file.as_raw_fd()))
            .map_err(|_| INVALID)?;
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            return Err(INVALID);
        }
        let owner = LibraryHandle(handle);
        let api = unsafe {
            Self {
                handle,
                _file: input.file,
                init: symbol(handle, c"seccomp_init")?,
                release: symbol(handle, c"seccomp_release")?,
                arch_add: symbol(handle, c"seccomp_arch_add")?,
                arch_native: symbol(handle, c"seccomp_arch_native")?,
                syscall: symbol(handle, c"seccomp_syscall_resolve_name")?,
                rule_add: symbol(handle, c"seccomp_rule_add_array")?,
                load: symbol(handle, c"seccomp_load")?,
            }
        };
        std::mem::forget(owner);
        if unsafe { (api.arch_native)() } != 0xc00000b7 {
            return Err(INVALID);
        }
        Ok(api)
    }
}
struct Context<'a> {
    api: &'a Api,
    pointer: *mut c_void,
}
impl Drop for Context<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.api.release)(self.pointer);
        }
    }
}
impl<'a> Context<'a> {
    fn new(api: &'a Api, default: u32) -> Result<Self> {
        let pointer = unsafe { (api.init)(default) };
        if pointer.is_null() {
            return Err(INVALID);
        }
        Ok(Self { api, pointer })
    }
    fn rule(&self, action: u32, name: &str, args: &[(u32, i32, u64)]) -> Result<()> {
        let name = CString::new(name).map_err(|_| INVALID)?;
        let syscall = unsafe { (self.api.syscall)(name.as_ptr()) };
        if syscall == -1 {
            return Err(INVALID);
        }
        let args: Vec<_> = args
            .iter()
            .map(|&(arg, op, value)| Comparison {
                arg,
                op,
                datum_a: value,
                datum_b: 0,
            })
            .collect();
        if unsafe {
            (self.api.rule_add)(
                self.pointer,
                action,
                syscall,
                args.len() as u32,
                args.as_ptr(),
            )
        } != 0
        {
            return Err(INVALID);
        }
        Ok(())
    }
}

fn require_zero_capability_actor() -> Result<()> {
    if unsafe { libc::getuid() } != 10004
        || unsafe { libc::geteuid() } != 10004
        || unsafe { libc::getgid() } != 10004
        || unsafe { libc::getegid() } != 10004
    {
        return Err(INVALID);
    }
    let mut raw = Vec::new();
    File::open("/proc/self/status")
        .map_err(|_| INVALID)?
        .take(65537)
        .read_to_end(&mut raw)
        .map_err(|_| INVALID)?;
    if raw.len() > 65536 {
        return Err(INVALID);
    }
    let text = std::str::from_utf8(&raw).map_err(|_| INVALID)?;
    let field = |name: &str| -> Result<&str> {
        let mut values = text
            .lines()
            .filter_map(|line| line.split_once(':'))
            .filter(|(key, _)| *key == name);
        let (_, value) = values.next().ok_or(INVALID)?;
        if values.next().is_some() {
            return Err(INVALID);
        }
        Ok(value.trim())
    };
    for name in ["Uid", "Gid"] {
        if field(name)?.split_whitespace().collect::<Vec<_>>() != ["10004"; 4] {
            return Err(INVALID);
        }
    }
    if !field("Groups")?.is_empty() || field("NoNewPrivs")? != "1" {
        return Err(INVALID);
    }
    for name in ["CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb"] {
        if u64::from_str_radix(field(name)?, 16).map_err(|_| INVALID)? != 0 {
            return Err(INVALID);
        }
    }
    Ok(())
}

pub(crate) fn install(profile: &Value, network: NetworkProfile) -> Result<Value> {
    require_zero_capability_actor()?;
    if network == NetworkProfile::PrivateLoopback {
        observe_private_loopback()?;
    }
    let api = Api::open()?;
    let base = Context::new(&api, ERRNO | 38)?;
    if unsafe { (api.arch_add)(base.pointer, 0x40000028) } != 0 {
        return Err(INVALID);
    }
    for rule in profile["syscalls"].as_array().ok_or(INVALID)? {
        let mut args = Vec::new();
        if let Some(items) = rule.get("args") {
            for arg in items.as_array().ok_or(INVALID)? {
                args.push((
                    arg["index"].as_u64().ok_or(INVALID)? as u32,
                    comparison(arg["op"].as_str().ok_or(INVALID)?)?,
                    arg["value"].as_u64().ok_or(INVALID)?,
                ));
            }
        }
        for name in rule["names"].as_array().ok_or(INVALID)? {
            base.rule(action(rule)?, name.as_str().ok_or(INVALID)?, &args)?;
        }
    }
    let sockets = Context::new(&api, ALLOW)?;
    for family in std::iter::once(0).chain(2..16) {
        if network == NetworkProfile::PrivateLoopback && matches!(family, 2 | 10) {
            continue;
        }
        sockets.rule(ERRNO | 1, "socket", &[(0, 4, family)])?;
    }
    sockets.rule(ERRNO | 1, "socket", &[(0, 6, 16)])?;
    sockets.rule(ERRNO | 1, "socket", &[(0, 4, 16), (2, 1, 0)])?;
    sockets.rule(ERRNO | 1, "socketpair", &[(0, 1, 1)])?;
    // Never continue actor startup after a partial install. The caller exits
    // on any error; neither layer replaces or clears an inherited filter.
    for context in [&base, &sockets] {
        if unsafe { (api.load)(context.pointer) } != 0 {
            return Err(INVALID);
        }
    }
    let mut families = vec!["AF_UNIX", "AF_NETLINK:NETLINK_ROUTE"];
    if network == NetworkProfile::PrivateLoopback {
        families.extend(["AF_INET:private-loopback", "AF_INET6:private-loopback"]);
    }
    Ok(
        json!({"schema":"product-vm-seccomp.v1","profile_sha256":PROFILE_SHA256,
        "library_sha256":LIBRARY_SHA256,"socket_families":families,
        "declared_network_profile":network.declaration(),"executable_abi":"aarch64","installed_layers":2}),
    )
}
