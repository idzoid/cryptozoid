package ec

import (
	"crypto/elliptic"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECDSAKeymanager(t *testing.T) {

	t.Run("Should convert to pem and back to key", func(t *testing.T) {
		pk, err := GenerateECDSAKey(elliptic.P256())

		if err != nil {
			t.Fatal(err)
		}
		km := NewECDSAP256KeyManager(pk)
		pkBytes, _ := km.KeyBytes()
		pubBytes, _ := km.KeyBytes()
		pemPk, err := km.KeyToPem()
		if err != nil {
			t.Fatal(err)
		}
		pkFromPem, err := km.PemToKey(pemPk)
		if err != nil {
			t.Fatal(err)
		}
		kmFromPem := NewECDSAP256KeyManager(pkFromPem)
		pkBytesFromPem, _ := kmFromPem.KeyBytes()
		pubBytesFromPem, _ := kmFromPem.KeyBytes()
		assert.Equal(t, pkBytes, pkBytesFromPem)

		pemPub, err := km.PublicToPem()
		if err != nil {
			t.Fatal(err)
		}
		pubFromPem, err := km.PemToPublic(pemPub)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, pubBytes, pubBytesFromPem)
		assert.Equal(t, km.Key(), pkFromPem)
		assert.Equal(t, km.Public(), pubFromPem)
	})
}
