package ec

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
)

// KeyManager defines an interface for managing ECDH keys and operations,
// including curve identification, shared secret derivation, and key
// serialization/deserialization.
type KeyManager interface {

	// CurveName returns the name of the elliptic curve being used (e.g.,
	// "P-256").
	CurveName() string

	// DeriveSharedSecret derives a shared secret given a peer's ECDH public
	// key. It is not mandatory to use SHA-256, but it is strongly recommended
	// to use some kind of hash or KDF over the raw shared secret before
	// deriving a symmetric key. SHA-256 is simple and secure for most cases.
	DeriveSharedSecret(peerPub *ecdh.PublicKey) ([]byte, error)

	// PemToPrivateKey parses a PEM-encoded private key and returns an ECDH
	// private key.
	PemToPrivateKey(b []byte) (*ecdh.PrivateKey, error)

	// PemToPublicKey parses a PEM-encoded public key and returns an ECDH
	// public key.
	PemToPublicKey(b []byte) (*ecdh.PublicKey, error)

	// PrivateKeyToPem serializes the private key as PEM-encoded bytes.
	PrivateKeyToPem() ([]byte, error)

	// PrivateKeyBytes returns the private key in PKCS#8 DER-encoded format.
	PrivateKeyBytes() ([]byte, error)

	// PublicKeyToPem serializes the public key as PEM-encoded bytes.
	PublicKeyToPem() ([]byte, error)

	// PublicKeyBytes returns the public key in PKIX DER-encoded format.
	PublicKeyBytes() ([]byte, error)
}

// GenPrivateKey generates a new ECDH private key using the provided elliptic
// curve.
//
// Example:
//
//	priv, err := GenPrivateKey(ecdh.P256())
func GenPrivateKey(curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// GenECP256PrivateKey generates a new ECDH private key using the P-256
// elliptic curve.
//
// Example:
//
//	priv, err := GenECP256PrivateKey()
func GenECP256PrivateKey() (*ecdh.PrivateKey, error) {
	return GenPrivateKey(ecdh.P256())
}

// ECP256PemToPrivateKey parses a PEM-encoded private key and returns an ECDH
// private key.
func ECP256PemToPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	priv, err := ecdh.P256().NewPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// ECP256PemToPublicKey parses a PEM-encoded public key and returns an ECDH public
// key.
func ECP256PemToPublicKey(b []byte) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := ecdh.P256().NewPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// ECP256KeyManager is a concrete KeyManager implementation for the P-256
// elliptic curve.
type ECP256KeyManager struct {
	Priv *ecdh.PrivateKey
}

// NewECP256KeyManager creates a new ECP256KeyManager using the provided
// private key.
//
// Example:
//
//	km := NewECP256KeyManager(priv)
func NewECP256KeyManager(priv *ecdh.PrivateKey) *ECP256KeyManager {
	k := &ECP256KeyManager{
		Priv: priv,
	}
	return k
}

// CurveName returns the name of the elliptic curve ("P-256").
func (k *ECP256KeyManager) CurveName() string {
	return "P-256"
}

// DeriveSharedSecret derives the shared secret with the given peer public key,
// returning the SHA-256 hash of the raw shared key.
func (k *ECP256KeyManager) DeriveSharedSecret(peerPub *ecdh.PublicKey) ([]byte, error) {
	shared, err := k.Priv.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(shared)
	return hash[:], nil
}

// PemToPrivateKey parses a PEM-encoded private key and returns an ECDH private
// key.
func (k *ECP256KeyManager) PemToPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	priv, err := ecdh.P256().NewPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// PemToPublicKey parses a PEM-encoded public key and returns an ECDH public
// key.
func (k *ECP256KeyManager) PemToPublicKey(b []byte) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	pub, err := ecdh.P256().NewPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

// PrivateKeyToPem serializes the private key as PEM-encoded bytes.
func (k *ECP256KeyManager) PrivateKeyToPem() ([]byte, error) {
	b, err := k.PrivateKeyBytes()
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(block), nil
}

// PrivateKeyBytes returns the private key in PKCS#8 DER-encoded format.
func (k *ECP256KeyManager) PrivateKeyBytes() ([]byte, error) {
	return k.Priv.Bytes(), nil
}

// PublicKeyToPem serializes the public key as PEM-encoded bytes.
func (k *ECP256KeyManager) PublicKeyToPem() ([]byte, error) {
	b, err := k.PublicKeyBytes()
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(block), nil
}

// PublicKeyBytes returns the public key in PKIX DER-encoded format.
func (k *ECP256KeyManager) PublicKeyBytes() ([]byte, error) {
	return k.Priv.PublicKey().Bytes(), nil
}
