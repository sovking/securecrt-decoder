// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.1
// Description: SecureCRT modern v2 AES-256-CBC decryption (variants "02" and "03") with checksum verification.
// License: MIT

package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

var (
	// ErrV2CiphertextTooShort indicates that the ciphertext is either too short or not 16-byte block aligned.
	ErrV2CiphertextTooShort = errors.New("v2 ciphertext must be at least 32 bytes and a multiple of 16 bytes")

	// ErrV2ChecksumMismatch indicates that the decrypted plaintext checksum does not match expected SHA-256 hash.
	ErrV2ChecksumMismatch = errors.New("v2 checksum verification failed: wrong passphrase or corrupted data")
)

// DecryptV2 decrypts SecureCRT v2 password payloads, supporting both variant "02" (basic AES-256-CBC)
// and variant "03" (AES-256-CBC with a 16-byte salt and iterative KDF).
func DecryptV2(data []byte, passphrase string, variant string) (string, error) {
	var key []byte
	var iv []byte
	var cipherData []byte

	if variant == "03" {
		if len(data) < 32 {
			return "", ErrV2CiphertextTooShort
		}
		salt := data[:16]
		cipherData = data[16:]

		derived, err := deriveV203KeyIV([]byte(passphrase), salt, 16, 48)
		if err != nil {
			return "", err
		}
		key = derived[:32]
		iv = derived[32:48]
	} else {
		// Variant "02": Key is SHA-256 of passphrase, IV is 16 zero bytes
		h := sha256.Sum256([]byte(passphrase))
		key = h[:]
		iv = make([]byte, 16)
		cipherData = data
	}

	if len(cipherData) == 0 || len(cipherData)%16 != 0 {
		return "", ErrV2CiphertextTooShort
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	plain := make([]byte, len(cipherData))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plain, cipherData)

	// Payload layout:
	// - First 4 bytes: Little-endian 32-bit unsigned integer (length L of plaintext password)
	// - Next L bytes: Plaintext password (UTF-8)
	// - Next 32 bytes: Expected SHA-256 checksum of the password
	if len(plain) < 36 { // 4 bytes length + 0 bytes minimum password + 32 bytes SHA-256
		return "", ErrV2ChecksumMismatch
	}

	pwLen := binary.LittleEndian.Uint32(plain[:4])
	if int(4+pwLen+32) > len(plain) {
		return "", ErrV2ChecksumMismatch
	}

	pwBytes := plain[4 : 4+pwLen]
	expectedHash := plain[4+pwLen : 4+pwLen+32]

	actualHash := sha256.Sum256(pwBytes)
	if subtle.ConstantTimeCompare(expectedHash, actualHash[:]) != 1 {
		return "", ErrV2ChecksumMismatch
	}

	return string(pwBytes), nil
}
