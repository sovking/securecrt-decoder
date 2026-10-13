// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.1
// Description: SecureCRT session .ini file parsing, protocol detection (SSH, RDP, Telnet, Serial), and credential extraction.
// License: MIT

package parser

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
	"strings"

	"github.com/sovking/securecrt-decoder/pkg/crypto"
)

// ParseINI reads and parses a SecureCRT .ini configuration file from disk.
func ParseINI(filePath string, sessionName string, passphrase string) (*Session, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return ParseINIContent(data, sessionName, filePath, passphrase)
}

// ParseINIContent parses raw bytes of a SecureCRT .ini configuration file.
// It supports all standard SecureCRT protocols including SSH2, SSH1, RDP, Telnet, and Serial.
func ParseINIContent(content []byte, sessionName string, filePath string, passphrase string) (*Session, error) {
	session := &Session{
		Name:       sessionName,
		SourceFile: filePath,
	}

	rawValues := make(map[string]string)

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// SecureCRT format follows: T:"Key"=Value where T is S (string) or D (dword/number)
		eqIdx := strings.Index(line, "=")
		if eqIdx == -1 {
			continue
		}

		left := strings.TrimSpace(line[:eqIdx])
		val := strings.TrimSpace(line[eqIdx+1:])

		// Strip surrounding quotes from value
		val = strings.Trim(val, "\"")

		// Extract inner key: S:"Key" -> Key
		key := extractKey(left)
		if key != "" {
			rawValues[strings.ToLower(key)] = val
		}
	}

	// 1. Hostname detection (checks generic, RDP, SSH, Telnet)
	if h, ok := rawValues["hostname"]; ok && h != "" {
		session.Hostname = h
	} else if h, ok := rawValues["[rdp] hostname"]; ok && h != "" {
		session.Hostname = h
	} else if h, ok := rawValues["[ssh2] hostname"]; ok && h != "" {
		session.Hostname = h
	} else if h, ok := rawValues["[telnet] hostname"]; ok && h != "" {
		session.Hostname = h
	}

	// 2. Protocol Name
	if p, ok := rawValues["protocol name"]; ok && p != "" {
		session.Protocol = p
	} else if p, ok := rawValues["protocol"]; ok && p != "" {
		session.Protocol = p
	}

	// 3. Port parsing and default fallbacks
	session.Port = parsePort(rawValues)
	if session.Port == 0 {
		switch strings.ToUpper(session.Protocol) {
		case "SSH2", "SSH1", "SSH":
			session.Port = 22
		case "RDP":
			session.Port = 3389
		case "TELNET":
			session.Port = 23
		}
	}

	// 4. Username detection (checks generic and protocol-prefixed fields)
	if u, ok := rawValues["username"]; ok && u != "" {
		session.Username = u
	} else if u, ok := rawValues["[rdp] username"]; ok && u != "" {
		session.Username = u
	} else if u, ok := rawValues["[ssh2] username"]; ok && u != "" {
		session.Username = u
	}

	// 5. Password and/or SSH Identity Key detection
	var encryptedPassword string
	isV2 := false

	if p2, ok := rawValues["password v2"]; ok && p2 != "" {
		encryptedPassword = p2
		isV2 = true
	} else if p2, ok := rawValues["[rdp] password v2"]; ok && p2 != "" {
		encryptedPassword = p2
		isV2 = true
	} else if p1, ok := rawValues["password"]; ok && p1 != "" {
		encryptedPassword = p1
		isV2 = false
	} else if p1, ok := rawValues["[rdp] password"]; ok && p1 != "" {
		encryptedPassword = p1
		isV2 = false
	}

	if encryptedPassword != "" {
		res, err := crypto.DecodePassword(encryptedPassword, passphrase)
		if err != nil {
			if isV2 && (err == crypto.ErrDecryptionFailed || err == crypto.ErrPassphraseRequired) {
				session.DecryptionError = "[DECRYPTION FAILED - PASSPHRASE REQUIRED]"
			} else {
				session.DecryptionError = "[DECRYPTION FAILED]"
			}
		} else {
			session.Password = res.Password
			session.PasswordVersion = string(res.Version)
		}
	}

	// If no password is set or decoded, extract SSH identity key file path
	if session.Password == "" {
		if id2, ok := rawValues["identity filename v2"]; ok && id2 != "" {
			session.SSHKeyPath = id2
		} else if id1, ok := rawValues["identity filename"]; ok && id1 != "" {
			session.SSHKeyPath = id1
		}
	}

	return session, nil
}

func extractKey(left string) string {
	startQuote := strings.Index(left, "\"")
	endQuote := strings.LastIndex(left, "\"")
	if startQuote != -1 && endQuote > startQuote {
		return left[startQuote+1 : endQuote]
	}
	return left
}

func parsePort(values map[string]string) int {
	candidates := []string{
		"[rdp] port",
		"[ssh2] port",
		"port",
		"[telnet] port",
		"[ssh1] port",
	}

	for _, cand := range candidates {
		if raw, ok := values[cand]; ok && raw != "" {
			// Check if formatted as 8-character hex dword (e.g., 00000d3d = 3389, 00000016 = 22)
			if len(raw) == 8 && isHex(raw) {
				if parsed, err := strconv.ParseInt(raw, 16, 32); err == nil {
					return int(parsed)
				}
			}
			// Check if standard decimal integer string
			if parsed, err := strconv.Atoi(raw); err == nil {
				return parsed
			}
		}
	}
	return 0
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
