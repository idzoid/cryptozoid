package ec

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
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

// GenerateECDHKey generates a new ECDH private key using the provided curve.
//
// Example:
//
//	priv, err := GenerateECDHKey(ecdh.P256())
func GenerateECDHKey(curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	return curve.GenerateKey(rand.Reader)
}

// GenerateECDHP256Key generates a new ECDH private key using P-256.
func GenerateECDHP256Key() (*ecdh.PrivateKey, error) {
	return GenerateECDHKey(ecdh.P256())
}

// GenerateECDHP384Key generates a new ECDH private key using P-384.
func GenerateECDHP384Key() (*ecdh.PrivateKey, error) {
	return GenerateECDHKey(ecdh.P384())
}

// GenerateECDHP521Key generates a new ECDH private key using P-521.
func GenerateECDHP521Key() (*ecdh.PrivateKey, error) {
	return GenerateECDHKey(ecdh.P521())
}

// ECDHPemToKey parses an ECDH private key from PKCS#8, SEC1, or raw curve
// private-key PEM data.
func ECDHPemToKey(b []byte) (*ecdh.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch key := key.(type) {
		case *ecdh.PrivateKey:
			return key, nil
		case *ecdsa.PrivateKey:
			return key.ECDH()
		}
	}

	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key.ECDH()
	}

	var lastErr error
	for _, curve := range []ecdh.Curve{ecdh.P256(), ecdh.P384(), ecdh.P521()} {
		key, err := curve.NewPrivateKey(block.Bytes)
		if err == nil {
			return key, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("unsupported ECDH private key")
	}
	return nil, lastErr
}

// ECDHPemToPublic parses an ECDH public key from PKIX or raw curve public-key
// PEM data.
func ECDHPemToPublic(b []byte) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		switch key := key.(type) {
		case *ecdh.PublicKey:
			return key, nil
		case *ecdsa.PublicKey:
			return key.ECDH()
		}
	}

	var lastErr error
	for _, curve := range []ecdh.Curve{ecdh.P256(), ecdh.P384(), ecdh.P521()} {
		key, err := curve.NewPublicKey(block.Bytes)
		if err == nil {
			return key, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("unsupported ECDH public key")
	}
	return nil, lastErr
}

// ECDHP256PemToKey parses a P-256 ECDH private key from PEM.
func ECDHP256PemToKey(b []byte) (*ecdh.PrivateKey, error) {
	return ecdhPrivateKeyForCurve(b, ecdh.P256())
}

// ECDHP384PemToKey parses a P-384 ECDH private key from PEM.
func ECDHP384PemToKey(b []byte) (*ecdh.PrivateKey, error) {
	return ecdhPrivateKeyForCurve(b, ecdh.P384())
}

// ECDHP521PemToKey parses a P-521 ECDH private key from PEM.
func ECDHP521PemToKey(b []byte) (*ecdh.PrivateKey, error) {
	return ecdhPrivateKeyForCurve(b, ecdh.P521())
}

// ECDHP256PemToPublic parses a P-256 ECDH public key from PEM.
func ECDHP256PemToPublic(b []byte) (*ecdh.PublicKey, error) {
	return ecdhPublicKeyForCurve(b, ecdh.P256())
}

// ECDHP384PemToPublic parses a P-384 ECDH public key from PEM.
func ECDHP384PemToPublic(b []byte) (*ecdh.PublicKey, error) {
	return ecdhPublicKeyForCurve(b, ecdh.P384())
}

// ECDHP521PemToPublic parses a P-521 ECDH public key from PEM.
func ECDHP521PemToPublic(b []byte) (*ecdh.PublicKey, error) {
	return ecdhPublicKeyForCurve(b, ecdh.P521())
}

func ecdhPrivateKeyForCurve(b []byte, curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	key, err := ECDHPemToKey(b)
	if err != nil {
		return nil, err
	}
	if key.Curve() != curve {
		return nil, errors.New("ECDH key curve does not match requested curve")
	}
	return key, nil
}

func ecdhPublicKeyForCurve(b []byte, curve ecdh.Curve) (*ecdh.PublicKey, error) {
	key, err := ECDHPemToPublic(b)
	if err != nil {
		return nil, err
	}
	if key.Curve() != curve {
		return nil, errors.New("ECDH key curve does not match requested curve")
	}
	return key, nil
}

// ECDHCurveKeyManager manages ECDH keys across the supported NIST curves.
type ECDHCurveKeyManager struct {
	key *ecdh.PrivateKey
}

// ECDHP256KeyManager is retained as a compatibility alias. New code should
// use ECDHCurveKeyManager through NewECDHKeyManager.
type ECDHP256KeyManager = ECDHCurveKeyManager

// NewECDHKeyManager creates a key manager for a supported ECDH curve.
func NewECDHKeyManager(priv *ecdh.PrivateKey) ECDHKeyManager {
	return &ECDHCurveKeyManager{key: priv}
}

// NewECDHP256KeyManager creates a key manager for a P-256 ECDH key.
func NewECDHP256KeyManager(priv *ecdh.PrivateKey) ECDHKeyManager {
	return NewECDHKeyManager(priv)
}

// NewECDHP384KeyManager creates a key manager for a P-384 ECDH key.
func NewECDHP384KeyManager(priv *ecdh.PrivateKey) ECDHKeyManager {
	return NewECDHKeyManager(priv)
}

// NewECDHP521KeyManager creates a key manager for a P-521 ECDH key.
func NewECDHP521KeyManager(priv *ecdh.PrivateKey) ECDHKeyManager {
	return NewECDHKeyManager(priv)
}

func ecdhCurveName(curve ecdh.Curve) string {
	switch curve {
	case ecdh.P256():
		return "P-256"
	case ecdh.P384():
		return "P-384"
	case ecdh.P521():
		return "P-521"
	default:
		return "Unknown"
	}
}

// CurveName returns the name of the managed elliptic curve.
func (k *ECDHCurveKeyManager) CurveName() string {
	return ecdhCurveName(k.key.Curve())
}

// DeriveSharedSecret derives the shared secret with the given peer public key,
// returning the SHA-256 hash of the raw shared key.
func (k *ECDHCurveKeyManager) DeriveSharedSecret(peerPub *ecdh.PublicKey) ([]byte, error) {
	shared, err := k.key.ECDH(peerPub)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(shared)
	return hash[:], nil
}

// PemToPrivateKey parses a PEM-encoded private key for the manager's curve.
func (k *ECDHCurveKeyManager) PemToPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	return ecdhPrivateKeyForCurve(b, k.key.Curve())
}

// PemToPublicKey parses a PEM-encoded public key for the manager's curve.
func (k *ECDHCurveKeyManager) PemToPublicKey(b []byte) (*ecdh.PublicKey, error) {
	return ecdhPublicKeyForCurve(b, k.key.Curve())
}

// PrivateKeyToPem serializes the private key as PEM-encoded bytes.
func (k *ECDHCurveKeyManager) PrivateKeyToPem() ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(k.key)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	return pem.EncodeToMemory(block), nil
}

// PrivateKeyBytes returns the private key in PKCS#8 DER-encoded format.
func (k *ECDHCurveKeyManager) PrivateKeyBytes() ([]byte, error) {
	return k.key.Bytes(), nil
}

// PublicKeyToPem serializes the public key as PEM-encoded bytes.
func (k *ECDHCurveKeyManager) PublicKeyToPem() ([]byte, error) {
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
func (k *ECDHCurveKeyManager) PublicKeyBytes() ([]byte, error) {
	return k.key.PublicKey().Bytes(), nil
}

// Key returns the managed ECDH private key.
func (k *ECDHCurveKeyManager) Key() *ecdh.PrivateKey {
	return k.key
}

// Public returns the managed ECDH public key.
func (k *ECDHCurveKeyManager) Public() crypto.PublicKey {
	return k.key.Public()
}
