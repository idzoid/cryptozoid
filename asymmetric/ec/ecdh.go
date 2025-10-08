package ec

import (
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// ECDHKeyManager defines an interface for managing ECDH keys and operations,
// including curve identification, shared secret derivation, and key
// serialization/deserialization.
type ECDHKeyManager interface {

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

	Key() *ecdh.PrivateKey

	Public() crypto.PublicKey
}

// GenerateECDHKey generates a new ECDH private key using the provided elliptic
// curve.
//
// Example:
//
//	priv, err := GenerateECDHKey(ecdh.P256())
func GenerateECDHKey(curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// GenerateECDHP256Key generates a new ECDH private key using the P-256
// elliptic curve.
//
// Example:
//
//	priv, err := GenerateECDHP256Key()
func GenerateECDHP256Key() (*ecdh.PrivateKey, error) {
	return GenerateECDHKey(ecdh.P256())
}

// ECDHP256PemToKey parses a PEM-encoded private key and returns an ECDH
// private key.
func ECDHP256PemToKey(b []byte) (*ecdh.PrivateKey, error) {
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

// ECDHP256PemToPublic parses a PEM-encoded public key and returns an ECDH
// public key.
func ECDHP256PemToPublic(b []byte) (*ecdh.PublicKey, error) {
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

// ECDHP256KeyManager is a concrete KeyManager implementation for the P-256
// elliptic curve.
type ECDHP256KeyManager struct {
	key *ecdh.PrivateKey
}

// NewECDHP256KeyManager creates a new Ecdh256KeyManager using the provided
// private key.
//
// Example:
//
//	km := NewECDHP256KeyManager(priv)
func NewECDHP256KeyManager(priv *ecdh.PrivateKey) ECDHKeyManager {
	k := &ECDHP256KeyManager{
		key: priv,
	}
	return k
}

// CurveName returns the name of the elliptic curve ("P-256").
func (k *ECDHP256KeyManager) CurveName() string {
	return "P-256"
}

// DeriveSharedSecret derives the shared secret with the given peer public key,
// returning the SHA-256 hash of the raw shared key.
func (k *ECDHP256KeyManager) DeriveSharedSecret(peerPub *ecdh.PublicKey) ([]byte, error) {
	shared, err := k.key.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(shared)
	return hash[:], nil
}

// PemToPrivateKey parses a PEM-encoded private key and returns an ECDH private
// key.
func (k *ECDHP256KeyManager) PemToPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
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
func (k *ECDHP256KeyManager) PemToPublicKey(b []byte) (*ecdh.PublicKey, error) {
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
func (k *ECDHP256KeyManager) PrivateKeyToPem() ([]byte, error) {
	fmt.Printf("Tipo real: %T\n", k.key)
	b, err := x509.MarshalPKCS8PrivateKey(k.key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Formato inválido para PRIVATE KEY: %s", err)
	}
	fmt.Printf("Tipo real: %T\n", key)
	return pem.EncodeToMemory(block), nil
}

// PrivateKeyBytes returns the private key in PKCS#8 DER-encoded format.
func (k *ECDHP256KeyManager) PrivateKeyBytes() ([]byte, error) {
	return k.key.Bytes(), nil
}

// PublicKeyToPem serializes the public key as PEM-encoded bytes.
func (k *ECDHP256KeyManager) PublicKeyToPem() ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(k.key.Public())
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
func (k *ECDHP256KeyManager) PublicKeyBytes() ([]byte, error) {
	return k.key.PublicKey().Bytes(), nil
}

func (k *ECDHP256KeyManager) Key() *ecdh.PrivateKey {
	return k.key
}

func (k *ECDHP256KeyManager) Public() crypto.PublicKey {
	return k.key.Public()
}
