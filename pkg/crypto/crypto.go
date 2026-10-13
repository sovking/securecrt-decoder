// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.1
// Description: Common crypto interfaces, types, and automated version cascade dispatcher.
// License: MIT

package crypto

import (
	"encoding/hex"
	"errors"
	"strings"
)

// Version identifies the encryption format version used by SecureCRT.
type Version string

const (
	// VersionV1 represents the legacy two-pass Blowfish-CBC format.
	VersionV1 Version = "v1"
	// VersionV202 represents the AES-256-CBC format without salt (SHA-256 of passphrase).
	VersionV202 Version = "v2 (02)"
	// VersionV203 represents the AES-256-CBC format with a 16-byte random salt and iterative KDF.
	VersionV203 Version = "v2 (03)"
)

// Result holds the plaintext decrypted password and the detected version format.
type Result struct {
	Password string
	Version  Version
}

var (
	// ErrEmptyInput indicates that the provided input is empty or contains only whitespace.
	ErrEmptyInput = errors.New("empty or invalid input data")
	// ErrInvalidHex indicates that the ciphertext string is not valid hexadecimal.
	ErrInvalidHex = errors.New("invalid hexadecimal string format")
	// ErrDecryptionFailed indicates that decryption could not be verified (checksum mismatch or malformed data).
	ErrDecryptionFailed = errors.New("decryption failed: incorrect passphrase or corrupted data")
	// ErrPassphraseRequired indicates that a master passphrase is required to decrypt this session.
	ErrPassphraseRequired = errors.New("config passphrase required for v2 session")
)

// cleanHex removes whitespace, common prefixes (02:, 03:, 0x), and returns the sanitized hex string and detected prefix.
func cleanHex(input string) (string, string) {
	s := strings.TrimSpace(input)
	prefix := ""

	if strings.HasPrefix(s, "02:") {
		prefix = "02"
		s = s[3:]
	} else if strings.HasPrefix(s, "03:") {
		prefix = "03"
		s = s[3:]
	}

	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "\t", "")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")

	return s, prefix
}

// DecodePassword attempts to decrypt a SecureCRT encrypted password string.
// It automatically detects whether the input belongs to v2 (variant 03 or 02) or v1,
// validates internal checksums, and returns the plaintext password.
func DecodePassword(rawCiphertext string, passphrase string) (*Result, error) {
	cleaned, prefix := cleanHex(rawCiphertext)
	if len(cleaned) == 0 {
		return nil, ErrEmptyInput
	}

	data, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, ErrInvalidHex
	}

	// 1. If explicit "03" prefix is present or matched:
	if prefix == "03" {
		pw, err := DecryptV2(data, passphrase, "03")
		if err == nil {
			return &Result{Password: pw, Version: VersionV203}, nil
		}
		return nil, err
	}

	// 2. If explicit "02" prefix is present:
	if prefix == "02" {
		pw, err := DecryptV2(data, passphrase, "02")
		if err == nil {
			return &Result{Password: pw, Version: VersionV202}, nil
		}
		return nil, err
	}

	// 3. Cascade auto-detection if no prefix is given:
	// Try v2 (02): common in modern SecureCRT configurations without a config passphrase.
	if len(data)%16 == 0 && len(data) >= 48 {
		if pw, err := DecryptV2(data, passphrase, "02"); err == nil {
			return &Result{Password: pw, Version: VersionV202}, nil
		}
	}

	// Try v2 (03) with salt:
	if len(data) >= 64 && (len(data)-16)%16 == 0 {
		if pw, err := DecryptV2(data, passphrase, "03"); err == nil {
			return &Result{Password: pw, Version: VersionV203}, nil
		}
	}

	// Try v1 (Two-pass Blowfish-CBC):
	if len(data) > 8 && len(data)%8 == 0 {
		if pw, err := DecryptV1(data); err == nil {
			return &Result{Password: pw, Version: VersionV1}, nil
		}
	}

	return nil, ErrDecryptionFailed
}
