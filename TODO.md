# TODO - SecureCRT Password Decoder

Development, testing, and release checklist for `securecrt-decoder`.

---

## [x] Phase 1: Project Setup & Architecture
- [x] Initialize Git repository (branch `main`).
- [x] Standard Go folder structure (`cmd/`, `pkg/crypto/`, `pkg/parser/`, `pkg/scanner/`, `testdata/`, `.github/`).
- [x] Write `AGENTS.md` with architectural guidelines and cryptographic specifications.
- [x] Create MIT license file (`LICENSE`).
- [x] Configure `go.mod` with pure-Go dependencies (`golang.org/x/crypto`).
- [x] Configure `.goreleaser.yaml` for 6 cross-platform targets (`linux/amd64`, `linux/arm64`, `windows/amd64`, `windows/arm64`, `darwin/amd64`, `darwin/arm64`).
- [x] Configure GitHub Actions for CI (`ci.yml`) and automated release (`release.yml`).
- [x] Create `TODO.md`.

---

## [x] Phase 2: Cryptographic Engine (`pkg/crypto`)
- [x] Common types and auto-detection dispatcher (`crypto.go`).
- [x] SecureCRT v1 decoder with two-pass Blowfish-CBC and UTF-16LE (`v1.go`).
- [x] SecureCRT v2 variant `02` decoder with AES-256-CBC and SHA-256 (`v2.go`).
- [x] SecureCRT v2 variant `03` Key Derivation Function (KDF) using SHA-512 and bcrypt_pbkdf (`kdf.go`).
- [x] SecureCRT v2 variant `03` AES-256-CBC decoder (`v2.go`).
- [x] Unit test suite covering all versions with regression test vectors (`crypto_test.go`).

---

## [x] Phase 3: Session Parser (`pkg/parser`)
- [x] Data model `Session` (`session.go`).
- [x] SecureCRT `.ini` parser handling `S:"..."` and `D:"..."` prefixes, port dword/hex conversion, and cleaning (`ini.go`).
- [x] Fallback to SSH private key (`Identity Filename V2`) when password is unset (`ini.go`).
- [x] Unit test suite for INI parser (`ini_test.go`).

---

## [x] Phase 4: Recursive File System Scanner (`pkg/scanner`)
- [x] Single file and recursive directory tree traversal (`scanner.go`).
- [x] Hierarchical session naming based on directory hierarchy.
- [x] Fault tolerance: ignore internal metadata files like `__FolderData__.ini` and handle corrupted files gracefully.
- [x] Unit test suite for filesystem scanner (`scanner_test.go`).

---

## [x] Phase 5: Command-Line Interface (`cmd/securecrt-decoder`)
- [x] CLI entrypoint with flag parsing (`-path`, `-passphrase`, `-format`, `-version`) (`main.go`).
- [x] Human-readable terminal table output.
- [x] Structured JSON output for scripting and pipelines.
- [x] Standard CSV output for spreadsheets and auditing.
- [x] Automatic discovery of default SecureCRT configuration folders on Windows, macOS, and Linux.

---

## [x] Phase 6: Documentation & Validation
- [x] Sample regression test files in `testdata/` (`router_cisco_v1.ini`, `switch_core_v2.ini`, `nested/bastion_key.ini`).
- [x] Professional `README.md` with usage examples, default paths, and legal disclaimer.
- [x] Verified unit tests and cross-compilation across all 6 targets.
- [x] Initial commit and push to GitHub repository.
- [x] Automated release via GoReleaser (v1.0.0) published with binaries for 6 targets.
