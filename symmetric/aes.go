package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

// EncryptAESGCM encrypts the given plaintext using AES in Galois/Counter Mode
// (GCM).
//
// Parameters:
//   - key: The symmetric key to use for AES (must be 16, 24, or 32 bytes for
//     AES-128/192/256).
//   - nonce: A unique nonce for this encryption operation. Must have the size
//     returned by aesgcm.NonceSize() (typically 12 bytes).
//   - plaintext: The data to encrypt.
//
// Returns:
//   - ciphertext: The encrypted and authenticated data. The authentication tag
//     (MAC) is appended automatically by GCM.
//   - error: Non-nil if there was a problem during encryption.
//
// Notes:
//   - The caller is responsible for generating a unique nonce for each
//     encryption call with the same key.
//   - Nonce reuse with the same key destroys security!
func EncryptAESGCM(key, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts data encrypted with AES in Galois/Counter Mode (GCM).
//
// Parameters:
//   - key: The symmetric key used for AES (must be 16, 24, or 32 bytes).
//   - nonce: The nonce that was used during encryption (must be the same as
//     used for encryption).
//   - ciphertext: The encrypted data with the GCM authentication tag appended.
//
// Returns:
//   - plaintext: The original data if decryption and authentication succeed.
//   - error: Non-nil if decryption fails, the key/nonce is wrong, or
//     authentication fails.
func DecryptAESGCM(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// AES-GCM standard nonce size in bytes
const AESGCM_NONCE_SIZE = 12

func NewAESGCMNonce() ([]byte, error) {
	nonce := make([]byte, AESGCM_NONCE_SIZE)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return nonce, nil
}
