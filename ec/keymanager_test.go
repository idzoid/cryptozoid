package ec

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeymanager(t *testing.T) {

	t.Run("Should convert to pem and back to key", func(t *testing.T) {
		pk, err := GenEcdhP256PrivateKey()

		if err != nil {
			t.Fatal(err)
		}
		km := NewEcdhP256KeyManager(pk)
		pkBytes, _ := km.PrivateKeyBytes()
		pubBytes, _ := km.PublicKeyBytes()
		pemPk, err := km.PrivateKeyToPem()
		if err != nil {
			t.Fatal(err)
		}
		pkFromPem, err := km.PemToPrivateKey(pemPk)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, pkBytes, pkFromPem.Bytes())

		pemPub, err := km.PublicKeyToPem()
		if err != nil {
			t.Fatal(err)
		}
		pubFromPem, err := km.PemToPublicKey(pemPub)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, pubBytes, pubFromPem.Bytes())
	})

	t.Run("Should generate shared secret between two parties", func(t *testing.T) {
		p1Priv, err := GenEcdhP256PrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		p1Km := NewEcdhP256KeyManager(p1Priv)

		p2Priv, err := GenEcdhP256PrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		p2Km := NewEcdhP256KeyManager(p2Priv)

		p1Shared, err := p1Km.DeriveSharedSecret(p2Priv.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		p2Shared, err := p2Km.DeriveSharedSecret(p1Priv.PublicKey())
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, hex.EncodeToString(p1Shared), hex.EncodeToString(p2Shared))
	})
}
