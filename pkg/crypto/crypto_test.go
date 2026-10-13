// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.0
// Description: Unit test suite for SecureCRT password encryption and decryption routines.
// License: MIT

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"golang.org/x/crypto/blowfish"
)

// encryptV1ForTest encrypts a plaintext string into SecureCRT v1 format for unit tests.
func encryptV1ForTest(plaintext string) (string, error) {
	// Encode as UTF-16LE with double-null termination
	runes := []rune(plaintext)
	u16 := utf16.Encode(runes)
	raw := make([]byte, (len(u16)+1)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(raw[i*2:i*2+2], v)
	}

	// Pad to 8-byte block multiple
	padLen := (8 - (len(raw) % 8)) % 8
	if padLen > 0 {
		raw = append(raw, make([]byte, padLen)...)
	}

	// Blowfish-CBC encryption with Key 2
	b2, err := blowfish.NewCipher(v1Key2)
	if err != nil {
		return "", err
	}
	enc2 := make([]byte, len(raw))
	cipher.NewCBCEncrypter(b2, v1IV).CryptBlocks(enc2, raw)

	// Prepend 4 random bytes and append 4 random bytes
	intermediate := make([]byte, len(enc2)+8)
	rand.Read(intermediate[:4])
	copy(intermediate[4:], enc2)
	rand.Read(intermediate[len(intermediate)-4:])

	// Blowfish-CBC encryption with Key 1
	b1, err := blowfish.NewCipher(v1Key1)
	if err != nil {
		return "", err
	}
	enc1 := make([]byte, len(intermediate))
	cipher.NewCBCEncrypter(b1, v1IV).CryptBlocks(enc1, intermediate)

	return hex.EncodeToString(enc1), nil
}

// encryptV202ForTest encrypts a plaintext string into SecureCRT v2-02 format for unit tests.
func encryptV202ForTest(password, passphrase string) (string, error) {
	pwBytes := []byte(password)
	h := sha256.Sum256(pwBytes)

	payload := make([]byte, 4+len(pwBytes)+32)
	binary.LittleEndian.PutUint32(payload[:4], uint32(len(pwBytes)))
	copy(payload[4:], pwBytes)
	copy(payload[4+len(pwBytes):], h[:])

	// Pad to 16-byte block multiple
	pad := (16 - (len(payload) % 16)) % 16
	if pad > 0 {
		payload = append(payload, make([]byte, pad)...)
	}

	keyHash := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(keyHash[:])
	if err != nil {
		return "", err
	}

	enc := make([]byte, len(payload))
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(enc, payload)

	return "02:" + hex.EncodeToString(enc), nil
}

// encryptV203ForTest encrypts a plaintext string into SecureCRT v2-03 format for unit tests.
func encryptV203ForTest(password, passphrase string) (string, error) {
	pwBytes := []byte(password)
	h := sha256.Sum256(pwBytes)

	payload := make([]byte, 4+len(pwBytes)+32)
	binary.LittleEndian.PutUint32(payload[:4], uint32(len(pwBytes)))
	copy(payload[4:], pwBytes)
	copy(payload[4+len(pwBytes):], h[:])

	pad := (16 - (len(payload) % 16)) % 16
	if pad > 0 {
		payload = append(payload, make([]byte, pad)...)
	}

	salt := make([]byte, 16)
	rand.Read(salt)

	derived, err := deriveV203KeyIV([]byte(passphrase), salt, 16, 48)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(derived[:32])
	if err != nil {
		return "", err
	}

	enc := make([]byte, len(payload))
	cipher.NewCBCEncrypter(block, derived[32:48]).CryptBlocks(enc, payload)

	total := append(salt, enc...)
	return "03:" + hex.EncodeToString(total), nil
}

func TestV1Decryption(t *testing.T) {
	passwords := []string{
		"admin123",
		"Secret!Pass#2024",
		"Router-Core#C1sc0",
		"simple",
		"VeryLongPasswordWithSpecialCharacters!@#$%^&*()_+",
	}

	for _, pw := range passwords {
		encHex, err := encryptV1ForTest(pw)
		if err != nil {
			t.Fatalf("Failed to encrypt v1 test password: %v", err)
		}

		res, err := DecodePassword(encHex, "")
		if err != nil {
			t.Fatalf("Failed to decode v1 password '%s': %v", pw, err)
		}

		if res.Password != pw {
			t.Errorf("Expected '%s', got '%s'", pw, res.Password)
		}
		if res.Version != VersionV1 {
			t.Errorf("Expected version '%s', got '%s'", VersionV1, res.Version)
		}
	}
}

func TestV202Decryption(t *testing.T) {
	tests := []struct {
		password   string
		passphrase string
	}{
		{"cisco123", ""},
		{"superSecret", "MyMasterPassphrase"},
		{"complex-password-1234", ""},
	}

	for _, tc := range tests {
		encHex, err := encryptV202ForTest(tc.password, tc.passphrase)
		if err != nil {
			t.Fatalf("Failed to encrypt v2-02: %v", err)
		}

		res, err := DecodePassword(encHex, tc.passphrase)
		if err != nil {
			t.Fatalf("Failed to decode v2-02 password '%s': %v", tc.password, err)
		}

		if res.Password != tc.password {
			t.Errorf("Expected '%s', got '%s'", tc.password, res.Password)
		}
		if res.Version != VersionV202 {
			t.Errorf("Expected version '%s', got '%s'", VersionV202, res.Version)
		}

		// Verify that decryption fails when providing an incorrect passphrase
		if tc.passphrase != "" {
			_, errWrong := DecodePassword(encHex, "WrongPassphrase")
			if errWrong == nil {
				t.Errorf("Decryption should have failed with incorrect passphrase")
			}
		}
	}
}

func TestV203Decryption(t *testing.T) {
	tests := []struct {
		password   string
		passphrase string
	}{
		{"switch-admin", ""},
		{"ProtectedPassword99!", "SecurePassphrase2026"},
	}

	for _, tc := range tests {
		encHex, err := encryptV203ForTest(tc.password, tc.passphrase)
		if err != nil {
			t.Fatalf("Failed to encrypt v2-03: %v", err)
		}

		res, err := DecodePassword(encHex, tc.passphrase)
		if err != nil {
			t.Fatalf("Failed to decode v2-03 password '%s': %v", tc.password, err)
		}

		if res.Password != tc.password {
			t.Errorf("Expected '%s', got '%s'", tc.password, res.Password)
		}
		if res.Version != VersionV203 {
			t.Errorf("Expected version '%s', got '%s'", VersionV203, res.Version)
		}
	}
}

func TestGenerateTestData(t *testing.T) {
	testDataDir := filepath.Join("..", "..", "testdata")
	if err := os.MkdirAll(filepath.Join(testDataDir, "nested"), 0755); err != nil {
		t.Fatalf("Failed to create testdata dir: %v", err)
	}

	// 1. Generate v1 sample session
	v1Enc, err := encryptV1ForTest("cisco_v1_secret")
	if err != nil {
		t.Fatalf("Failed to generate v1 test cipher: %v", err)
	}
	v1Content := fmt.Sprintf(`# SecureCRT v1 Legacy Session Sample
S:"Hostname"=10.1.1.1
S:"Protocol Name"=SSH2
D:"[SSH2] Port"=00000016
S:"Username"=cisco_admin
S:"Password"=%s
`, v1Enc)
	if err := os.WriteFile(filepath.Join(testDataDir, "router_cisco_v1.ini"), []byte(v1Content), 0644); err != nil {
		t.Fatalf("Failed to write router_cisco_v1.ini: %v", err)
	}

	// 2. Generate v2-02 sample session
	v2Enc, err := encryptV202ForTest("juniper_v2_secret", "")
	if err != nil {
		t.Fatalf("Failed to generate v2 test cipher: %v", err)
	}
	v2Content := fmt.Sprintf(`# SecureCRT v2 Modern Session Sample
S:"Hostname"=192.168.10.254
S:"Protocol Name"=SSH2
D:"Port"=00000016
S:"Username"=netops
S:"Password V2"=%s
`, v2Enc)
	if err := os.WriteFile(filepath.Join(testDataDir, "switch_core_v2.ini"), []byte(v2Content), 0644); err != nil {
		t.Fatalf("Failed to write switch_core_v2.ini: %v", err)
	}

	// 3. Generate nested SSH key sample session
	keyContent := `# SecureCRT SSH Key Identity Session Sample
S:"Hostname"=bastion.cloud.internal
S:"Protocol Name"=SSH2
D:"Port"=000008ae
S:"Username"=ubuntu
S:"Identity Filename V2"=/home/user/.ssh/id_ed25519
`
	if err := os.WriteFile(filepath.Join(testDataDir, "nested", "bastion_key.ini"), []byte(keyContent), 0644); err != nil {
		t.Fatalf("Failed to write bastion_key.ini: %v", err)
	}
}
