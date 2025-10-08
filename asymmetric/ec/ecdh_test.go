package ec

import (
	"crypto/elliptic"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECDHKeymanager(t *testing.T) {

	t.Run("Should generate shared secret between two parties", func(t *testing.T) {
		pk1, err := GenerateECDSAKey(elliptic.P256())
		if err != nil {
			t.Fatal(err)
		}
		ecdsaKm1 := NewECDSAP256KeyManager(pk1)
		p1Km, err := ecdsaKm1.ECDHKeyManager()
		if err != nil {
			t.Fatal(err)
		}

		pk2, err := GenerateECDSAKey(elliptic.P256())
		if err != nil {
			t.Fatal(err)
		}
		ecdsaKm2 := NewECDSAP256KeyManager(pk2)
		p2Km, err := ecdsaKm2.ECDHKeyManager()
		if err != nil {
			t.Fatal(err)
		}

		p1Shared, err := p1Km.DeriveSharedSecret(p2Km.Key().PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		p2Shared, err := p2Km.DeriveSharedSecret(p1Km.Key().PublicKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, hex.EncodeToString(p1Shared), hex.EncodeToString(p2Shared))
	})
}
