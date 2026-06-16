# drvcheck

A lightweight Windows CLI tool that enumerates all loaded kernel drivers, computes their SHA256 hashes, and checks them against the [LOLDrivers](https://loldrivers.io) database of known vulnerable drivers.

## Features

- Enumerates all loaded kernel drivers via `EnumDeviceDrivers`
- Resolves driver names and file paths via `GetDeviceDriverBaseNameW` / `GetDeviceDriverFileNameW`
- Converts NT device paths (`\SystemRoot\`, `\Device\HarddiskVolume...`, `\??\`, `\DosDevices\`) to standard Win32 paths
- Computes SHA256 hashes of driver files on disk using `CreateFileW` with shared access
- Matches hashes against a local LOLDrivers JSON database using O(1) HashMap lookups
- Attempts to enable `SeDebugPrivilege` for broader access
- Handles locked/inaccessible files gracefully with typed errors

## Build

Requires [Rust](https://rustup.rs/) (1.70+).

```
cargo build --release
```

Binary output: `target/release/drvcheck.exe`

## Usage

Place `loldrivers.json` in the same directory as the executable, then run from an elevated (Administrator) command prompt:

```
drvcheck.exe
```

The tool will:

1. Load `loldrivers.json` from the current directory
2. Enumerate all loaded kernel drivers
3. Resolve each driver's file path and compute its SHA256 hash
4. Check each hash against the vulnerability database
5. Print a table of all drivers with addresses, names, hashes, and paths
6. Print a prominent alert block for any matched vulnerable drivers

### Example output

```
[+] Loaded 485 known vulnerable driver hashes from loldrivers.json

Base Address       Base Name                                         SHA256                                                    Resolved Path
----------------------------------------------------------------------------------------------------------------------------------------------------
0xFFFFF80012340000 ntoskrnl.exe                                       a1b2c3d4...                                               C:\Windows\System32\ntoskrnl.exe
0xFFFFF80012560000 WdFilter.sys                                       e5f6a7b8...                                               C:\Windows\System32\drivers\WdFilter.sys

!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!  VULNERABLE DRIVER DETECTED                                           !!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  Driver Name    : aswTask.sys
  Product        : Avast
  Publisher      : AVAST Software
  Risk Level     : malicious
  File Path      : C:\Windows\System32\drivers\aswTask.sys
  SHA256         : e5f6a7b8...
  Tags           : avast, vulnerable-driver
  REMEDIATION    : Remove or quarantine the driver file. Block via HVCI/GPO.
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

[+] Vulnerability scan complete. 1 match(es) found out of 187 drivers.
```

## LOLDrivers database

Download the JSON database from:

```
https://www.loldrivers.io/api/drivers.json
```

Save it as `loldrivers.json` next to the executable. The tool expects the standard LOLDrivers schema with `KnownVulnerableSamples` containing `SHA256` hashes.

## How it works

1. **Driver enumeration** -- Calls `EnumDeviceDrivers` from `psapi.dll` to get the base address of every loaded kernel module, then resolves names via `GetDeviceDriverBaseNameW` and `GetDeviceDriverFileNameW`.

2. **Path conversion** -- Converts NT-style paths returned by the API to accessible Win32 paths:
   - `\SystemRoot\...` -> `C:\Windows\...` (via `GetWindowsDirectoryW`)
   - `\Device\HarddiskVolumeN\...` -> `X:\...` (via `QueryDosDeviceW` per drive letter)
   - `\??\X:\...` and `\DosDevices\X:\...` -> `X:\...` (prefix strip)

3. **File hashing** -- Opens each driver file with `CreateFileW` using `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE` to handle files that may be locked by the system, then reads in 64KB chunks into a SHA256 hasher.

4. **Vulnerability matching** -- Loads the LOLDrivers JSON, deserializes all `KnownVulnerableSamples`, and builds a `HashMap<[u8; 32], VulnMatch>` for instant O(1) lookups by SHA256 hash bytes.

## Dependencies

| Crate | Purpose |
|-------|---------|
| `sha2` | SHA256 hashing |
| `hex` | Hex encode/decode |
| `serde` + `serde_json` | JSON parsing |

## Requirements

- Windows (uses Win32 APIs: `psapi`, `kernel32`, `advapi32`)
- Run as Administrator for full driver enumeration and file access
