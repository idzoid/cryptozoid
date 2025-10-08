package ec

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// ECDSAKeyManager defines an interface for managing ECDSA keys and operations,
// including curve identification, and key serialization/deserialization.
type ECDSAKeyManager interface {

	// CurveName returns the name of the elliptic curve being used (e.g.,
	// "P-256").
	CurveName() string

	// Key returns k as a [ecdsa.PrivateKey].
	Key() *ecdsa.PrivateKey

	ECDHKeyManager() (ECDHKeyManager, error)

	// Key returns k as a [ecdsa.PublicKey].
	Public() *ecdsa.PublicKey

	// PemToKey parses a PEM-encoded private key and returns an ECDSA private
	// key.
	PemToKey(b []byte) (*ecdsa.PrivateKey, error)

	// PemToPublicKey parses a PEM-encoded public key and returns an ECDSA
	// public key.
	PemToPublic(b []byte) (*ecdsa.PublicKey, error)

	// KeyToPem serializes the private key as PEM-encoded bytes.
	KeyToPem() ([]byte, error)

	// KeyBytes returns the private key in PKCS#8 DER-encoded format.
	KeyBytes() ([]byte, error)

	// PublicToPem serializes the public key as PEM-encoded bytes.
	PublicToPem() ([]byte, error)

	// PublicKeyBytes returns the public key in PKIX DER-encoded format.
	PublicBytes() ([]byte, error)
}

func CurveName(k *ecdsa.PrivateKey) string {
	switch k.Curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	}
	return "Unknown"
}

// GenerateECDSAKey generates a new ECDSA private key using the provided elliptic
// curve.
//
// Example:
//
//	priv, err := GenerateECDSAKey(elliptic.P256())
func GenerateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// ECDSAP256KeyManager is a concrete KeyManager implementation for the P-256
// elliptic curve.
type ECDSAP256KeyManager struct {
	key *ecdsa.PrivateKey
}

// NewEcdhP256KeyManager creates a new Ecdh256KeyManager using the provided
// private key.
//
// Example:
//
//	km := NewEcdhP256KeyManager(priv)
func NewECDSAP256KeyManager(key *ecdsa.PrivateKey) ECDSAKeyManager {
	km := &ECDSAP256KeyManager{
		key: key,
	}
	return km
}

// ECDSAP256PemToKey parses a PEM-encoded private key and returns an ECDH
// private key.
func ECDSAP256PemToPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
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

// CurveName returns the name of the elliptic curve being used (e.g.,
// "P-256")
func (km *ECDSAP256KeyManager) CurveName() string {
	return CurveName(km.key)
}

// Key returns k as a [ecdsa.PrivateKey].
func (km *ECDSAP256KeyManager) Key() *ecdsa.PrivateKey {
	return km.key
}

// Public returns k as a [ecdsa.PublicKey].
func (km *ECDSAP256KeyManager) Public() *ecdsa.PublicKey {
	return &km.key.PublicKey
}

func (km *ECDSAP256KeyManager) ECDHKeyManager() (ECDHKeyManager, error) {
	ecdhKey, err := km.key.ECDH()
	if err != nil {
		return nil, err
	}
	return NewECDHP256KeyManager(ecdhKey), nil
}

// PemToKey parses a PEM-encoded private key and returns an ECDSA
// private key.
func (km *ECDSAP256KeyManager) PemToKey(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
	}

	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}
	return priv, nil
}

// PemToPublic parses a PEM-encoded public key and returns an ECDSA
// public key.
func (km *ECDSAP256KeyManager) PemToPublic(b []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	priv, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return priv, nil
}

// KeyToPem serializes the private key as PEM-encoded bytes.
func (km *ECDSAP256KeyManager) KeyToPem() ([]byte, error) {
	b, err := km.KeyBytes()
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(block), nil
}

// KeyBytes returns the private key in PKCS#8 DER-encoded format.
func (km *ECDSAP256KeyManager) KeyBytes() ([]byte, error) {
	if km.key == nil {
		return nil, errors.New("private key is nil")
	}
	return x509.MarshalPKCS8PrivateKey(km.key)
}

// PublicToPem serializes the public key as PEM-encoded bytes.
func (km *ECDSAP256KeyManager) PublicToPem() ([]byte, error) {
	b, err := km.PublicBytes()
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(block), nil
}

// PublicBytes returns the public key in PKIX DER-encoded format.
func (km *ECDSAP256KeyManager) PublicBytes() ([]byte, error) {
	if km.key == nil {
		return nil, errors.New("private key is nil")
	}
	pub := &km.key.PublicKey
	return x509.MarshalPKIXPublicKey(pub)
}
