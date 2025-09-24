package pack

import (
	"bytes"
	"testing"
)

func TestBigEndianCombineAndSeparate(t *testing.T) {
	tests := []struct {
		name       string
		ciphertext []byte
		nonce      []byte
	}{
		{"normal", []byte{0x41, 0x42, 0x43}, []byte{0x01, 0x02, 0x03}},
		{"empty ciphertext", []byte{}, []byte{0x01, 0x02}},
		{"empty nonce", []byte{0xAA, 0xBB}, []byte{}},
		{"both empty", []byte{}, []byte{}},
		{"long ciphertext", bytes.Repeat([]byte{0x10}, 256), []byte{0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packed := BigEndianCombine(tt.ciphertext, tt.nonce)
			gotCiphertext, gotNonce, err := BigEndianSeparate(packed)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(tt.ciphertext, gotCiphertext) {
				t.Errorf("ciphertext mismatch: want %v got %v", tt.ciphertext, gotCiphertext)
			}
			if !bytes.Equal(tt.nonce, gotNonce) {
				t.Errorf("nonce mismatch: want %v got %v", tt.nonce, gotNonce)
			}
		})
	}
}

func TestBigEndianSeparateErrors(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
	}{
		{"nil input", nil},
		{"empty input", []byte{}},
		{"one byte only", []byte{0x00}},
		{"prefix bigger than slice", []byte{0x00, 0x10}},
		{"prefix much bigger than slice", []byte{0x01, 0x00}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := BigEndianSeparate(c.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
