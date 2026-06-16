mod hash;
mod vuln;

use std::ffi::c_void;
use std::path::Path;
use std::ptr;

type HANDLE = *mut c_void;
type BOOL = i32;
type DWORD = u32;
type PCWSTR = *const u16;

const TOKEN_ADJUST_PRIVILEGES: DWORD = 0x0020;
const TOKEN_QUERY: DWORD = 0x0008;
const SE_PRIVILEGE_ENABLED: DWORD = 0x00000002;

#[repr(C)]
struct LUID {
    low_part: u32,
    high_part: i32,
}

#[repr(C)]
struct LUID_AND_ATTRIBUTES {
    luid: LUID,
    attributes: u32,
}

#[repr(C)]
struct TOKEN_PRIVILEGES {
    privilege_count: u32,
    privileges: [LUID_AND_ATTRIBUTES; 1],
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> HANDLE;
    fn OpenProcessToken(process_handle: HANDLE, desired_access: DWORD, token_handle: *mut HANDLE) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
}

#[link(name = "advapi32")]
extern "system" {
    fn LookupPrivilegeValueW(lp_system_name: PCWSTR, lp_name: PCWSTR, lp_luid: *mut LUID) -> BOOL;
    fn AdjustTokenPrivileges(token_handle: HANDLE, disable_all: BOOL, new_state: *const TOKEN_PRIVILEGES, buffer_length: DWORD, previous_state: *mut TOKEN_PRIVILEGES, return_length: *mut DWORD) -> BOOL;
}

#[link(name = "psapi")]
extern "system" {
    fn EnumDeviceDrivers(lp_drivers: *mut HANDLE, cb: DWORD, lp_needed: *mut DWORD) -> BOOL;
    fn GetDeviceDriverBaseNameW(image_base: HANDLE, lp_base_name: *mut u16, size: DWORD) -> DWORD;
    fn GetDeviceDriverFileNameW(image_base: HANDLE, lp_file_name: *mut u16, size: DWORD) -> DWORD;
}

unsafe fn enable_debug_privilege() -> bool {
    let mut token: HANDLE = ptr::null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token) == 0 {
        return false;
    }

    let mut luid = LUID { low_part: 0, high_part: 0 };
    let name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
    if LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) == 0 {
        CloseHandle(token);
        return false;
    }

    let tp = TOKEN_PRIVILEGES {
        privilege_count: 1,
        privileges: [LUID_AND_ATTRIBUTES {
            luid,
            attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    let ok = AdjustTokenPrivileges(token, 0, &tp, 0, ptr::null_mut(), ptr::null_mut());
    CloseHandle(token);
    ok != 0
}

unsafe fn get_wstring(buf: *const u16, max_len: usize) -> String {
    if buf.is_null() {
        return String::new();
    }
    let mut len = 0;
    while len < max_len && *buf.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(buf, len))
}

const DB_PATH: &str = "loldrivers.json";

fn main() {
    let db = match vuln::VulnDb::load(Path::new(DB_PATH)) {
        Ok(db) => {
            eprintln!("[+] Loaded {} known vulnerable driver hashes from {}", db.count(), DB_PATH);
            Some(db)
        }
        Err(e) => {
            eprintln!("[!] Could not load {}: {}", DB_PATH, e);
            eprintln!("    Continuing without vulnerability matching.");
            None
        }
    };

    unsafe {
        let _ = enable_debug_privilege();

        let mut needed: DWORD = 0;
        EnumDeviceDrivers(ptr::null_mut(), 0, &mut needed);

        if needed == 0 {
            eprintln!("Failed to query driver list size");
            std::process::exit(1);
        }

        let count = (needed / std::mem::size_of::<HANDLE>() as DWORD) as usize;
        let mut bases: Vec<HANDLE> = vec![ptr::null_mut(); count];
        let mut returned: DWORD = 0;

        if EnumDeviceDrivers(bases.as_mut_ptr(), needed, &mut returned) == 0 {
            eprintln!("EnumDeviceDrivers failed");
            std::process::exit(1);
        }

        let actual = (returned / std::mem::size_of::<HANDLE>() as DWORD) as usize;
        let mut name_buf = vec![0u16; 260];
        let mut path_buf = vec![0u16; 512];

        println!("{:<18} {:<50} {:<66} {}", "Base Address", "Base Name", "SHA256", "Resolved Path");
        println!("{}", "-".repeat(180));

        let mut vuln_count: usize = 0;

        for i in 0..actual {
            let base = bases[i];

            let name_len = GetDeviceDriverBaseNameW(base, name_buf.as_mut_ptr(), 260);
            let name = get_wstring(name_buf.as_ptr(), name_len as usize);

            let path_len = GetDeviceDriverFileNameW(base, path_buf.as_mut_ptr(), 512);
            let sys_path = get_wstring(path_buf.as_ptr(), path_len as usize);

            let result = hash::hash_driver(&sys_path);

            let hash_str = result.sha256.as_deref().unwrap_or("N/A");
            let resolved = &result.resolved_path;

            println!("{:#018X} {:<50} {:<66} {}", base as usize, name, hash_str, resolved);

            if let Some(ref e) = result.error {
                eprintln!("  WARNING: {} - {}", name, e);
            }

            if let Some(ref db) = db {
                if let Some(ref h) = result.sha256 {
                    if let Some(vuln) = db.lookup(h) {
                        vuln_count += 1;
                        vuln::print_vuln_alert(&result, vuln);
                    }
                }
            }
        }

        if db.is_some() {
            eprintln!("[+] Vulnerability scan complete. {} match(es) found out of {} drivers.", vuln_count, actual);
        }
    }
}
