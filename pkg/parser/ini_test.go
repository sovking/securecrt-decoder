// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.0
// Description: Unit test suite for SecureCRT .ini parsing across SSH, RDP, and Telnet protocols.
// License: MIT

package parser

import (
	"strings"
	"testing"
)

func TestParseINIContent(t *testing.T) {
	iniContent := `
# Test configuration session
S:"Hostname"=192.168.1.100
S:"Protocol Name"=SSH2
D:"[SSH2] Port"=00000016
S:"Username"=network_admin
S:"Identity Filename V2"=C:\Users\Admin\.ssh\id_ed25519
`

	session, err := ParseINIContent([]byte(iniContent), "Switches/Core-01", "/path/to/Core-01.ini", "")
	if err != nil {
		t.Fatalf("Failed to parse INI content: %v", err)
	}

	if session.Name != "Switches/Core-01" {
		t.Errorf("Expected name 'Switches/Core-01', got '%s'", session.Name)
	}
	if session.Hostname != "192.168.1.100" {
		t.Errorf("Expected hostname '192.168.1.100', got '%s'", session.Hostname)
	}
	if session.Protocol != "SSH2" {
		t.Errorf("Expected protocol 'SSH2', got '%s'", session.Protocol)
	}
	if session.Port != 22 {
		t.Errorf("Expected port 22 (from 00000016), got %d", session.Port)
	}
	if session.Username != "network_admin" {
		t.Errorf("Expected username 'network_admin', got '%s'", session.Username)
	}
	if session.SSHKeyPath != `C:\Users\Admin\.ssh\id_ed25519` {
		t.Errorf("Unexpected SSHKeyPath: '%s'", session.SSHKeyPath)
	}
}

func TestParseINIDecimalPort(t *testing.T) {
	iniContent := `
S:"Hostname"=bastion.example.com
S:"Protocol Name"=SSH2
D:"Port"=2222
S:"Username"=devops
`
	session, err := ParseINIContent([]byte(iniContent), "Bastion", "Bastion.ini", "")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if session.Port != 2222 {
		t.Errorf("Expected port 2222, got %d", session.Port)
	}
}

func TestParseINIRDPSession(t *testing.T) {
	iniContent := `
S:"Protocol Name"=RDP
S:"[RDP] Hostname"=win-server-2022.corp.local
D:"[RDP] Port"=00000d3d
S:"[RDP] Username"=Administrator
`
	session, err := ParseINIContent([]byte(iniContent), "Windows-DC", "Windows-DC.ini", "")
	if err != nil {
		t.Fatalf("Parse error for RDP session: %v", err)
	}
	if session.Hostname != "win-server-2022.corp.local" {
		t.Errorf("Expected hostname 'win-server-2022.corp.local', got '%s'", session.Hostname)
	}
	if session.Protocol != "RDP" {
		t.Errorf("Expected protocol 'RDP', got '%s'", session.Protocol)
	}
	if session.Port != 3389 {
		t.Errorf("Expected RDP port 3389 (from 00000d3d), got %d", session.Port)
	}
	if session.Username != "Administrator" {
		t.Errorf("Expected username 'Administrator', got '%s'", session.Username)
	}
}

func TestParseINIWithPasswordV2(t *testing.T) {
	iniContent := `
S:"Hostname"=10.0.0.1
S:"Protocol Name"=SSH2
D:"Port"=00000016
S:"Username"=cisco
S:"Password V2"=02:INVALID_DATA_FOR_FAILURE
`
	session, err := ParseINIContent([]byte(iniContent), "Router", "Router.ini", "")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	if !strings.Contains(session.DecryptionError, "FAILED") {
		t.Errorf("Expected decryption error string, got: '%s'", session.DecryptionError)
	}
}
