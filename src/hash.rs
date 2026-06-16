use std::ffi::c_void;
use std::fmt;
use sha2::{Sha256, Digest};

type HANDLE = *mut c_void;
type BOOL = i32;
type DWORD = u32;
type PCWSTR = *const u16;
type LPWSTR = *mut u16;

const INVALID_HANDLE_VALUE: HANDLE = !0isize as HANDLE;
const FILE_SHARE_READ: DWORD = 0x00000001;
const FILE_SHARE_WRITE: DWORD = 0x00000002;
const FILE_SHARE_DELETE: DWORD = 0x00000004;
const OPEN_EXISTING: DWORD = 3;
const FILE_ATTRIBUTE_NORMAL: DWORD = 0x80;
const GENERIC_READ: DWORD = 0x80000000;

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        lp_file_name: PCWSTR,
        dw_desired_access: DWORD,
        dw_share_mode: DWORD,
        lp_security_attributes: *const c_void,
        dw_creation_disposition: DWORD,
        dw_flags_and_attributes: DWORD,
        h_template_file: HANDLE,
    ) -> HANDLE;

    fn ReadFile(
        h_file: HANDLE,
        lp_buffer: *mut u8,
        n_number_of_bytes_to_read: DWORD,
        lp_number_of_bytes_read: *mut DWORD,
        lp_overlapped: *mut c_void,
    ) -> BOOL;

    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn GetWindowsDirectoryW(lp_buffer: LPWSTR, u_size: DWORD) -> DWORD;
    fn QueryDosDeviceW(lp_device_name: PCWSTR, lp_target_path: LPWSTR, ucch_max: DWORD) -> DWORD;
}

#[derive(Debug)]
pub enum HashError {
    PathConversionFailed(String),
    FileNotFound(String),
    AccessDenied(String),
    ReadFailed(String),
}

impl fmt::Display for HashError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashError::PathConversionFailed(p) => write!(f, "path conversion failed: {}", p),
            HashError::FileNotFound(p) => write!(f, "file not found: {}", p),
            HashError::AccessDenied(p) => write!(f, "access denied: {}", p),
            HashError::ReadFailed(p) => write!(f, "read failed: {}", p),
        }
    }
}

#[allow(dead_code)]
pub struct DriverHash {
    pub sys_path: String,
    pub resolved_path: String,
    pub sha256: Option<String>,
    pub error: Option<HashError>,
}

unsafe fn get_wstring_buf(buf: *const u16, max_len: usize) -> String {
    if buf.is_null() {
        return String::new();
    }
    let mut len = 0;
    while len < max_len && *buf.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(buf, len))
}

fn wide_string(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn get_windows_dir() -> Option<String> {
    unsafe {
        let mut buf = [0u16; 260];
        let len = GetWindowsDirectoryW(buf.as_mut_ptr(), 260);
        if len == 0 || len >= 260 {
            return None;
        }
        Some(get_wstring_buf(buf.as_ptr(), len as usize))
    }
}

fn query_dos_device(drive: char) -> Option<String> {
    unsafe {
        let device_name = format!("{}:\0", drive);
        let device_name_w = wide_string(&device_name);
        let mut target_buf = [0u16; 512];
        let len = QueryDosDeviceW(device_name_w.as_ptr(), target_buf.as_mut_ptr(), 512);
        if len == 0 {
            return None;
        }
        Some(get_wstring_buf(target_buf.as_ptr(), len as usize))
    }
}

fn resolve_harddisk_volume(sys_path: &str) -> Option<String> {
    let prefix = "\\Device\\HarddiskVolume";
    if !sys_path.starts_with(prefix) {
        return None;
    }

    let rest = &sys_path[prefix.len()..];
    let vol_end = rest.find('\\').unwrap_or(rest.len());
    let vol_num = &rest[..vol_end];
    let relative = if vol_end < rest.len() { &rest[vol_end..] } else { "" };

    let device_prefix = format!("{}{}", prefix, vol_num);

    for drive in 'C'..='Z' {
        if let Some(target) = query_dos_device(drive) {
            if target.eq_ignore_ascii_case(&device_prefix) {
                let win_path = format!("{}:{}", drive, relative);
                return Some(win_path);
            }
        }
    }
    None
}

pub fn resolve_sys_path(sys_path: &str) -> Result<String, HashError> {
    if sys_path.is_empty() {
        return Err(HashError::PathConversionFailed("empty path".into()));
    }

    if sys_path.starts_with("\\SystemRoot\\") {
        if let Some(win_dir) = get_windows_dir() {
            let rest = &sys_path["\\SystemRoot".len()..];
            return Ok(format!("{}{}", win_dir, rest));
        }
        return Err(HashError::PathConversionFailed(
            "failed to get Windows directory".into(),
        ));
    }

    if sys_path.starts_with("\\Device\\HarddiskVolume") {
        if let Some(resolved) = resolve_harddisk_volume(sys_path) {
            return Ok(resolved);
        }
        return Err(HashError::PathConversionFailed(format!(
            "could not resolve volume: {}",
            sys_path
        )));
    }

    if sys_path.starts_with("\\??\\") {
        return Ok(sys_path[4..].to_string());
    }

    if sys_path.starts_with("\\DosDevices\\") {
        return Ok(sys_path["\\DosDevices\\".len()..].to_string());
    }

    Ok(sys_path.to_string())
}

unsafe fn read_file_sha256(win_path: &str) -> Result<String, HashError> {
    let path_w = wide_string(win_path);

    let h_file = CreateFileW(
        path_w.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        std::ptr::null(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        std::ptr::null_mut(),
    );

    if h_file == INVALID_HANDLE_VALUE {
        let err = std::io::Error::last_os_error();
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if code == 2 {
            return Err(HashError::FileNotFound(win_path.to_string()));
        }
        if code == 5 {
            return Err(HashError::AccessDenied(win_path.to_string()));
        }
        return Err(HashError::ReadFailed(format!("{}: {}", win_path, err)));
    }

    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut bytes_read: DWORD = 0;

    loop {
        let ok = ReadFile(
            h_file,
            buf.as_mut_ptr(),
            buf.len() as DWORD,
            &mut bytes_read,
            std::ptr::null_mut(),
        );

        if ok == 0 || bytes_read == 0 {
            break;
        }
        hasher.update(&buf[..bytes_read as usize]);
    }

    CloseHandle(h_file);

    let hash = hasher.finalize();
    Ok(hex::encode(hash))
}

pub fn hash_driver(sys_path: &str) -> DriverHash {
    let resolved = match resolve_sys_path(sys_path) {
        Ok(p) => p,
        Err(e) => {
            return DriverHash {
                sys_path: sys_path.to_string(),
                resolved_path: String::new(),
                sha256: None,
                error: Some(e),
            };
        }
    };

    match unsafe { read_file_sha256(&resolved) } {
        Ok(hash) => DriverHash {
            sys_path: sys_path.to_string(),
            resolved_path: resolved,
            sha256: Some(hash),
            error: None,
        },
        Err(e) => DriverHash {
            sys_path: sys_path.to_string(),
            resolved_path: resolved,
            sha256: None,
            error: Some(e),
        },
    }
}
