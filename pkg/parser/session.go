// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.0
// Description: Data models for SecureCRT sessions and extracted credentials.
// License: MIT

package parser

// Session represents the extracted metadata and decrypted credentials from a SecureCRT session file.
type Session struct {
	Name            string `json:"name"`                       // Session name or hierarchical folder path (e.g., "Network/Switches/Core-01")
	Protocol        string `json:"protocol"`                   // Connection protocol (SSH2, SSH1, Telnet, RDP, Serial, etc.)
	Hostname        string `json:"hostname"`                   // Target IP address or hostname
	Port            int    `json:"port"`                       // Connection port (e.g., 22, 23, 3389)
	Username        string `json:"username"`                   // Username
	Password        string `json:"password"`                   // Decrypted plaintext password
	PasswordVersion string `json:"password_version,omitempty"` // Detected cryptographic version (v1, v2 (02), v2 (03))
	SSHKeyPath      string `json:"ssh_key_path,omitempty"`     // Path to SSH private key identity file if password is not set
	SourceFile      string `json:"source_file"`                // Absolute path to the source .ini configuration file
	DecryptionError string `json:"decryption_error,omitempty"` // Decryption status error message if passphrase is required or verification failed
}
