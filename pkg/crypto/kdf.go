// Project: SecureCRT Password Decoder (securecrt-decoder)
// Version: 1.0.1
// Description: SecureCRT v2 (03) Key Derivation Function based on bcrypt_pbkdf and SHA-512.
// License: MIT

package crypto

import (
	"crypto/sha512"
	"errors"

	"golang.org/x/crypto/blowfish"
)

const kdfBlockSize = 32

var kdfMagic = []byte("OxychromaticBlowfishSwatDynamite")

// deriveV203KeyIV implements the Key Derivation Function (KDF) used in SecureCRT v2 variant "03".
// It is based on OpenBSD's bcrypt_pbkdf using SHA-512 to generate 48 bytes total:
// the first 32 bytes serve as the AES-256 key, and the trailing 16 bytes serve as the AES IV.
// It gracefully accepts an empty password string ("") when no master passphrase was configured.
func deriveV203KeyIV(password, salt []byte, rounds, keyLen int) ([]byte, error) {
	if rounds < 1 {
		return nil, errors.New("kdf: number of rounds must be at least 1")
	}
	if len(salt) == 0 {
		return nil, errors.New("kdf: salt cannot be empty")
	}
	if keyLen > 1024 {
		return nil, errors.New("kdf: key length exceeds maximum allowed")
	}

	numBlocks := (keyLen + kdfBlockSize - 1) / kdfBlockSize
	key := make([]byte, numBlocks*kdfBlockSize)

	// Compute SHA-512 of the password (works even for empty 0-byte password)
	h := sha512.New()
	h.Write(password)
	shapass := h.Sum(nil)

	shasalt := make([]byte, 0, sha512.Size)
	cnt := make([]byte, 4)
	tmp := make([]byte, kdfBlockSize)

	for block := 1; block <= numBlocks; block++ {
		h.Reset()
		h.Write(salt)
		cnt[0] = byte(block >> 24)
		cnt[1] = byte(block >> 16)
		cnt[2] = byte(block >> 8)
		cnt[3] = byte(block)
		h.Write(cnt)

		bcryptHash(tmp, shapass, h.Sum(shasalt))

		out := make([]byte, kdfBlockSize)
		copy(out, tmp)
		for i := 2; i <= rounds; i++ {
			h.Reset()
			h.Write(tmp)
			bcryptHash(tmp, shapass, h.Sum(shasalt))
			for j := 0; j < len(out); j++ {
				out[j] ^= tmp[j]
			}
		}

		for i, v := range out {
			key[i*numBlocks+(block-1)] = v
		}
	}

	return key[:keyLen], nil
}

// bcryptHash performs the core Blowfish key expansion and 64-round cipher permutation
// with the fixed "OxychromaticBlowfishSwatDynamite" constant.
func bcryptHash(out, shapass, shasalt []byte) {
	c, err := blowfish.NewSaltedCipher(shapass, shasalt)
	if err != nil {
		panic(err)
	}
	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(shasalt, c)
		blowfish.ExpandKey(shapass, c)
	}
	copy(out, kdfMagic)
	for i := 0; i < 32; i += 8 {
		for j := 0; j < 64; j++ {
			c.Encrypt(out[i:i+8], out[i:i+8])
		}
	}
	// Byte swap for little-endian compatibility
	for i := 0; i < 32; i += 4 {
		out[i+3], out[i+2], out[i+1], out[i] = out[i], out[i+1], out[i+2], out[i+3]
	}
}
