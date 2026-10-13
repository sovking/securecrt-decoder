// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.0
// Description: Unit test suite for recursive session directory discovery and metadata filtering.
// License: MIT

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanner(t *testing.T) {
	// Create a temporary directory structure mimicking SecureCRT Sessions hierarchy
	tmpDir, err := os.MkdirTemp("", "securecrt_test_*")
	if err != nil {
		t.Fatalf("Failed to create tmpDir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	subDir := filepath.Join(tmpDir, "Network", "Datacenter")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatalf("Failed to create subDir: %v", err)
	}

	// 1. Root-level session file
	s1 := `
S:"Hostname"=10.10.10.1
S:"Protocol Name"=SSH2
D:"Port"=00000016
S:"Username"=root
`
	if err := os.WriteFile(filepath.Join(tmpDir, "Root-Server.ini"), []byte(s1), 0644); err != nil {
		t.Fatalf("Failed to write root session file: %v", err)
	}

	// 2. Nested subfolder session file
	s2 := `
S:"Hostname"=192.168.100.1
S:"Protocol Name"=Telnet
D:"Port"=00000017
S:"Username"=cisco
`
	if err := os.WriteFile(filepath.Join(subDir, "Core-Switch.ini"), []byte(s2), 0644); err != nil {
		t.Fatalf("Failed to write nested session file: %v", err)
	}

	// 3. Metadata file that must be skipped (__FolderData__.ini)
	sFolder := `S:"Filter"=0`
	if err := os.WriteFile(filepath.Join(subDir, "__FolderData__.ini"), []byte(sFolder), 0644); err != nil {
		t.Fatalf("Failed to write __FolderData__.ini: %v", err)
	}

	scn := New("")
	sessions, err := scn.Scan(tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if len(sessions) != 2 {
		t.Fatalf("Expected 2 sessions, got %d", len(sessions))
	}

	foundRoot := false
	foundNested := false

	for _, s := range sessions {
		if s.Name == "Root-Server" && s.Hostname == "10.10.10.1" {
			foundRoot = true
		}
		if s.Name == "Network/Datacenter/Core-Switch" && s.Hostname == "192.168.100.1" {
			foundNested = true
		}
	}

	if !foundRoot {
		t.Errorf("Root-Server session was not properly discovered")
	}
	if !foundNested {
		t.Errorf("Nested Network/Datacenter/Core-Switch session was not properly discovered")
	}
}
