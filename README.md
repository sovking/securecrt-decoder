# SecureCRT Password Decoder (`securecrt-decoder`)

[![CI](https://github.com/sovking/securecrt-decoder/actions/workflows/ci.yml/badge.svg)](https://github.com/sovking/securecrt-decoder/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)

A fast, standalone, pure-Go CLI utility designed for system administrators, DevOps engineers, and security auditors to inspect SecureCRT session configuration files (`.ini`), extract connection metadata, decode saved passwords, or extract SSH private key paths.

---

## Features

- **Full SecureCRT Version Support:**
  - **v1**: Legacy two-pass Blowfish-CBC encryption.
  - **v2 (02)**: Modern AES-256-CBC without salt (key derived from SHA-256 of passphrase, defaults to empty).
  - **v2 (03)**: Hardened AES-256-CBC with 16-byte random salt and iterative KDF.
- **Recursive Directory Traversal:**
  - Recursively walks SecureCRT `Sessions/` folders and preserves folder hierarchy in session names (e.g., `Datacenter/Milan/Core-Switch-01`).
  - Automatically skips internal SecureCRT metadata files like `__FolderData__.ini`.
- **SSH Key Identification:**
  - If a session authenticates via an SSH key rather than a saved password, the path to the private key (`Identity Filename V2`) is automatically extracted and displayed.
- **Auto-Detection of Default Session Folders:**
  - Automatically locates standard SecureCRT configuration folders across Windows, macOS, and Linux if no path is passed.
- **Zero Runtime Dependencies (Pure Go):**
  - Compiled with `CGO_ENABLED=0` as a standalone static executable without requiring any C libraries or external runtimes.
- **Multi-Platform Support:**
  - Native pre-compiled binaries available for **8 architectures**:
    - **Linux**: `amd64` (x86_64), `arm64`
    - **FreeBSD**: `amd64` (x86_64), `arm64` (FreeBSD 13, 14, and 15)
    - **Windows**: `amd64` (x86_64), `arm64`
    - **macOS**: `amd64` (Intel), `arm64` (Apple Silicon M1/M2/M3/M4)
- **Multiple Output Formats:**
  - Terminal-friendly formatted table (default).
  - **JSON** (`-f json`) for scripting and automation pipelines.
  - **CSV** (`-f csv`) for spreadsheet export and auditing.

---

## Installation

### 1. Pre-compiled Binaries (Recommended)
Download the pre-compiled binary for your operating system and architecture directly from [GitHub Releases](https://github.com/sovking/securecrt-decoder/releases).

Extract the archive and move the binary to your `PATH` (e.g., `/usr/local/bin` on Linux/macOS or `C:\Windows\System32` on Windows).

### 2. Using `go install`
If you have Go installed on your machine:

```bash
go install github.com/sovking/securecrt-decoder/cmd/securecrt-decoder@latest
```

### 3. Build from Source
```bash
git clone https://github.com/sovking/securecrt-decoder.git
cd securecrt-decoder
go build -o securecrt-decoder ./cmd/securecrt-decoder
```

---

## Usage

```text
SecureCRT Password Decoder

Usage:
  securecrt-decoder [flags] [path]

Flags:
  -f, --format string       Output format: table, json, or csv (default "table")
  -p, --passphrase string   Configuration master passphrase (for protected v2 sessions)
      --show-empty          Include sessions with no saved passwords or SSH keys
  -v, --version             Print version information and exit
  -h, --help                Show help message
```

### Examples

#### 1. Scan the Default Sessions Directory
If you run `securecrt-decoder` without arguments, it will automatically search for your system's default SecureCRT directory:

```bash
securecrt-decoder
```

#### 2. Scan a Specific Directory or .ini File
```bash
# Scan a custom Sessions directory
securecrt-decoder /path/to/SecureCRT/Config/Sessions

# Inspect a single session file
securecrt-decoder /path/to/Sessions/Switch-01.ini
```

#### 3. Output as JSON or CSV
```bash
# Export all sessions to JSON
securecrt-decoder -f json /path/to/Sessions > sessions.json

# Export all sessions to CSV
securecrt-decoder -f csv /path/to/Sessions > sessions.csv
```

#### 4. Provide a Master Passphrase for Protected v2 Sessions
If your SecureCRT installation is protected by a master configuration passphrase:

```bash
securecrt-decoder -p "MySecretPassphrase" /path/to/Sessions
```

---

## Sample Output

```text
SESSION                         PROTOCOL   HOST                     PORT   USERNAME      PASSWORD / SSH KEY                 VERSION
-------                         --------   ----                     ----   --------      ------------------                 -------
Datacenter/Core-Switch-01       SSH2       192.168.10.1             22     cisco_admin   C1sc0#S3cur3!                      v2 (02)
Routers/Edge-BGP-02             SSH2       10.0.0.1                 22     netops        R0ut3r!P@ss                        v1
Cloud/Bastion-Host              SSH2       bastion.prod.internal    2222   ubuntu        [KEY] /home/admin/.ssh/id_ed25519  SSH Key

Total sessions found: 3
```

---

## Default SecureCRT Session Paths

| Operating System | Default Configuration Path |
| :--- | :--- |
| **Windows** | `%APPDATA%\VanDyke\Config\Sessions` |
| **macOS** | `~/Library/Application Support/VanDyke/SecureCRT/Config/Sessions` |
| **Linux** | `~/.vandyke/SecureCRT/Config/Sessions` |

---

## Responsible Use & Disclaimer

This software is developed and distributed for authorized system administration, session migration (e.g., migrating sessions from SecureCRT to OpenSSH, Termius, or Ansible), backup, and security audit purposes only. 

Users are solely responsible for ensuring that they have proper authorization before accessing configuration files. The author declines any responsibility for misuse or unauthorized access.

---

## License

This project is licensed under the [MIT License](LICENSE).
