// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.0
// Description: Recursive directory traversal, file discovery, and hierarchy-aware session naming.
// License: MIT

package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sovking/securecrt-decoder/pkg/parser"
)

// Scanner handles discovery and parsing of SecureCRT .ini configuration files.
type Scanner struct {
	Passphrase string
	Warnings   []string
}

// New creates a new Scanner instance with an optional master configuration passphrase.
func New(passphrase string) *Scanner {
	return &Scanner{
		Passphrase: passphrase,
		Warnings:   make([]string, 0),
	}
}

// Scan processes a single .ini file or recursively walks an entire directory tree.
func (s *Scanner) Scan(targetPath string) ([]parser.Session, error) {
	info, err := os.Stat(targetPath)
	if err != nil {
		return nil, fmt.Errorf("target path inaccessible: %w", err)
	}

	if !info.IsDir() {
		// Single file parsing mode
		sessionName := strings.TrimSuffix(filepath.Base(targetPath), filepath.Ext(targetPath))
		sess, err := parser.ParseINI(targetPath, sessionName, s.Passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to parse file %s: %w", targetPath, err)
		}
		return []parser.Session{*sess}, nil
	}

	// Recursive directory scanning mode
	var sessions []parser.Session

	err = filepath.WalkDir(targetPath, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			s.Warnings = append(s.Warnings, fmt.Sprintf("failed to access %s: %v", path, walkErr))
			return nil
		}

		if d.IsDir() {
			return nil
		}

		fileName := d.Name()
		lowerName := strings.ToLower(fileName)

		// Filter only .ini files and exclude SecureCRT internal folder metadata files
		if !strings.HasSuffix(lowerName, ".ini") || lowerName == "__folderdata__.ini" {
			return nil
		}

		relPath, err := filepath.Rel(targetPath, path)
		if err != nil {
			relPath = fileName
		}

		// Strip .ini extension and normalize path separators to '/' for hierarchical session naming
		sessionName := strings.TrimSuffix(relPath, filepath.Ext(relPath))
		sessionName = filepath.ToSlash(sessionName)

		sess, err := parser.ParseINI(path, sessionName, s.Passphrase)
		if err != nil {
			s.Warnings = append(s.Warnings, fmt.Sprintf("corrupted or invalid session file %s: %v", path, err))
			return nil
		}

		// Only include sessions that have at least Hostname, Username, Password, or an SSH Key
		if sess.Hostname != "" || sess.Username != "" || sess.Password != "" || sess.SSHKeyPath != "" {
			sessions = append(sessions, *sess)
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return sessions, nil
}
