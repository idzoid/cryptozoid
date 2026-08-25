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

	// Public returns k as a [ecdsa.PublicKey].
	Public() *ecdsa.PublicKey

	// PemToKey parses a PEM-encoded private key and returns an ECDSA private
	// key.
	PemToKey(b []byte) (*ecdsa.PrivateKey, error)

	// PemToPublic parses a PEM-encoded public key and returns an ECDSA public
	// key.
	PemToPublic(b []byte) (*ecdsa.PublicKey, error)

	// KeyToPem serializes the private key as PEM-encoded bytes.
	KeyToPem() ([]byte, error)

	// KeyBytes returns the private key in PKCS#8 DER-encoded format.
	KeyBytes() ([]byte, error)

	// PublicToPem serializes the public key as PEM-encoded bytes.
	PublicToPem() ([]byte, error)

	// PublicBytes returns the public key in PKIX DER-encoded format.
	PublicBytes() ([]byte, error)
}

// CurveName returns the standard name of the supported NIST curve.
func CurveName(k *ecdsa.PrivateKey) string {
	if k == nil {
		return "Unknown"
	}

	switch k.Curve {
	case elliptic.P256():
		return "P-256"
	case elliptic.P384():
		return "P-384"
	case elliptic.P521():
		return "P-521"
	default:
		return "Unknown"
	}
}

// GenerateECDSAKey generates a new ECDSA private key using the provided
// elliptic curve.
//
// Example:
//
//	priv, err := GenerateECDSAKey(elliptic.P256())
func GenerateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// PemToECDSAKey parses a PKCS#8 PEM-encoded private key and returns an ECDSA
// private key.
func PemToECDSAKey(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("the provided key is not ECDSA")
	}
	return pk, nil
}

// PemToECDSAPublic parses a PKIX PEM-encoded public key and returns an ECDSA
// public key.
func PemToECDSAPublic(b []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("the provided key is not ECDSA")
	}
	return pk, nil
}

// ECDSAPemToPrivateKey parses an ECDSA private key from PEM and converts it
// to the corresponding ECDH private key.
func ECDSAPemToPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
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
		return nil, errors.New("the provided key is not ECDSA")
	}
	return priv.ECDH()
}

// ECDSAP256PemToPrivateKey parses a P-256 ECDSA private key from PEM and
// converts it to the corresponding ECDH private key.
func ECDSAP256PemToPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	return ecdsaPrivateKeyForCurve(b, ecdh.P256())
}

// ECDSAP384PemToPrivateKey parses a P-384 ECDSA private key from PEM and
// converts it to the corresponding ECDH private key.
func ECDSAP384PemToPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	return ecdsaPrivateKeyForCurve(b, ecdh.P384())
}

// ECDSAP521PemToPrivateKey parses a P-521 ECDSA private key from PEM and
// converts it to the corresponding ECDH private key.
func ECDSAP521PemToPrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	return ecdsaPrivateKeyForCurve(b, ecdh.P521())
}

func ecdsaPrivateKeyForCurve(b []byte, curve ecdh.Curve) (*ecdh.PrivateKey, error) {
	key, err := ECDSAPemToPrivateKey(b)
	if err != nil {
		return nil, err
	}
	if key.Curve() != curve {
		return nil, errors.New("ECDSA key curve does not match requested curve")
	}
	return key, nil
}

// ECDSACurveKeyManager manages ECDSA keys across the supported NIST curves.
type ECDSACurveKeyManager struct {
	key *ecdsa.PrivateKey
}

// ECDSAP256KeyManager is retained as a compatibility alias. New code should
// use ECDSACurveKeyManager through NewECDSAKeyManager.
type ECDSAP256KeyManager = ECDSACurveKeyManager

// NewECDSAKeyManager creates a key manager for a supported ECDSA curve.
func NewECDSAKeyManager(key *ecdsa.PrivateKey) ECDSAKeyManager {
	return &ECDSACurveKeyManager{key: key}
}

// NewECDSAP256KeyManager creates a key manager for a P-256 ECDSA key.
func NewECDSAP256KeyManager(key *ecdsa.PrivateKey) ECDSAKeyManager {
	return NewECDSAKeyManager(key)
}

// NewECDSAP384KeyManager creates a key manager for a P-384 ECDSA key.
func NewECDSAP384KeyManager(key *ecdsa.PrivateKey) ECDSAKeyManager {
	return NewECDSAKeyManager(key)
}

// NewECDSAP521KeyManager creates a key manager for a P-521 ECDSA key.
func NewECDSAP521KeyManager(key *ecdsa.PrivateKey) ECDSAKeyManager {
	return NewECDSAKeyManager(key)
}

// CurveName returns the name of the elliptic curve being used.
func (km *ECDSACurveKeyManager) CurveName() string {
	return CurveName(km.key)
}

// Key returns the managed ECDSA private key.
func (km *ECDSACurveKeyManager) Key() *ecdsa.PrivateKey {
	return km.key
}

// Public returns the managed ECDSA public key.
func (km *ECDSACurveKeyManager) Public() *ecdsa.PublicKey {
	return &km.key.PublicKey
}

// ECDHKeyManager converts the managed ECDSA key to an ECDH key manager while
// preserving its curve.
func (km *ECDSACurveKeyManager) ECDHKeyManager() (ECDHKeyManager, error) {
	ecdhKey, err := km.key.ECDH()
	if err != nil {
		return nil, err
	}
	return NewECDHKeyManager(ecdhKey), nil
}

// PemToKey parses a PEM-encoded private key and returns an ECDSA private key.
func (km *ECDSACurveKeyManager) PemToKey(b []byte) (*ecdsa.PrivateKey, error) {
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

// PemToPublic parses a PEM-encoded public key and returns an ECDSA public key.
func (km *ECDSACurveKeyManager) PemToPublic(b []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return pub, nil
}

// KeyToPem serializes the private key as PEM-encoded bytes.
func (km *ECDSACurveKeyManager) KeyToPem() ([]byte, error) {
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
func (km *ECDSACurveKeyManager) KeyBytes() ([]byte, error) {
	if km.key == nil {
		return nil, errors.New("private key is nil")
	}
	return x509.MarshalPKCS8PrivateKey(km.key)
}

// PublicToPem serializes the public key as PEM-encoded bytes.
func (km *ECDSACurveKeyManager) PublicToPem() ([]byte, error) {
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
func (km *ECDSACurveKeyManager) PublicBytes() ([]byte, error) {
	if km.key == nil {
		return nil, errors.New("private key is nil")
	}
	return x509.MarshalPKIXPublicKey(&km.key.PublicKey)
}
