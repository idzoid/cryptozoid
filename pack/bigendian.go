package pack

import (
	"encoding/binary"
	"errors"
)

// BigEndianCombine packs ciphertext and nonce with a BigEndian uint16 prefix
// for ciphertext length.
func BigEndianCombine(ciphertext, nonce []byte) []byte {
	lenPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lenPrefix, uint16(len(ciphertext)))
	return append(append(lenPrefix, ciphertext...), nonce...)
}

// BigEndianSeparate unpacks ciphertext and nonce from a packed []byte with
// BigEndian uint16 prefix.
func BigEndianSeparate(packed []byte) (ciphertext, nonce []byte, err error) {
	if len(packed) < 2 {
		return nil, nil, errors.New("input too short")
	}
	cipherLen := binary.BigEndian.Uint16(packed[:2])
	if len(packed) < int(2+cipherLen) {
		return nil, nil, errors.New("ciphertext length prefix exceeds input size")
	}
	ciphertext = packed[2 : 2+cipherLen]
	nonce = packed[2+cipherLen:]
	return ciphertext, nonce, nil
}
