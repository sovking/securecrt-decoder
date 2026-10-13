// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.0
// Description: SecureCRT legacy v1 two-pass Blowfish-CBC decryption with UTF-16LE decoding.
// License: MIT

package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"unicode/utf16"

	"golang.org/x/crypto/blowfish"
)

var (
	// v1Key1 is the primary hardcoded 16-byte Blowfish key for SecureCRT v1 decryption.
	v1Key1 = []byte{0x24, 0xa6, 0x3d, 0xde, 0x5b, 0xd3, 0xb3, 0x82, 0x9c, 0x7e, 0x06, 0xf4, 0x08, 0x16, 0xaa, 0x07}

	// v1Key2 is the secondary hardcoded 16-byte Blowfish key for SecureCRT v1 decryption.
	v1Key2 = []byte{0x5f, 0xb0, 0x45, 0xa2, 0x94, 0x17, 0xd9, 0x16, 0xc6, 0xc6, 0xa2, 0xff, 0x06, 0x41, 0x82, 0xb7}

	// v1IV is the static 8-byte zero initialization vector for CBC mode.
	v1IV = make([]byte, 8)
)

var (
	// ErrV1CiphertextTooShort indicates that the ciphertext length is not a multiple of 8 or is <= 8 bytes.
	ErrV1CiphertextTooShort = errors.New("v1 ciphertext must be a multiple of 8 bytes and longer than 8 bytes")

	// ErrV1Malformed indicates that the decrypted intermediate payload does not match expected length criteria.
	ErrV1Malformed = errors.New("malformed v1 intermediate ciphertext")
)

// DecryptV1 decrypts passwords stored in legacy SecureCRT v1 sessions.
// It executes two consecutive Blowfish-CBC decryptions using static hardcoded keys,
// strips 4-byte prefixes and suffixes, and decodes the resulting UTF-16LE text.
func DecryptV1(ciphertext []byte) (string, error) {
	if len(ciphertext) <= 8 || len(ciphertext)%8 != 0 {
		return "", ErrV1CiphertextTooShort
	}

	// Pass 1: Blowfish-CBC decryption with Key 1
	block1, err := blowfish.NewCipher(v1Key1)
	if err != nil {
		return "", err
	}

	pt1 := make([]byte, len(ciphertext))
	mode1 := cipher.NewCBCDecrypter(block1, v1IV)
	mode1.CryptBlocks(pt1, ciphertext)

	// Strip first 4 bytes and last 4 bytes
	if len(pt1) <= 8 {
		return "", ErrV1Malformed
	}
	intermediate := pt1[4 : len(pt1)-4]
	if len(intermediate) == 0 || len(intermediate)%8 != 0 {
		return "", ErrV1Malformed
	}

	// Pass 2: Blowfish-CBC decryption with Key 2
	block2, err := blowfish.NewCipher(v1Key2)
	if err != nil {
		return "", err
	}

	pt2 := make([]byte, len(intermediate))
	mode2 := cipher.NewCBCDecrypter(block2, v1IV)
	mode2.CryptBlocks(pt2, intermediate)

	// Find the UTF-16LE null terminator (0x00 0x00)
	end := len(pt2)
	for i := 0; i+1 < len(pt2); i += 2 {
		if pt2[i] == 0 && pt2[i+1] == 0 {
			end = i
			break
		}
	}

	// Convert UTF-16LE code units to a Go UTF-8 string
	u16 := make([]uint16, end/2)
	for i := 0; i < len(u16); i++ {
		u16[i] = binary.LittleEndian.Uint16(pt2[i*2 : i*2+2])
	}

	return string(utf16.Decode(u16)), nil
}
