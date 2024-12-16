package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
)

type PublicKey []byte

const publicKeySize = ed25519.PublicKeySize

// TODO: add other encryption types
const publicKeyEncodingPrefix = "Ed25519,"

func (pub PublicKey) String() string {
	return pub.Encode()
}

func (pub PublicKey) Encode() string {
	return publicKeyEncodingPrefix + base64.StdEncoding.EncodeToString(pub)
}

func (pub PublicKey) ID64() uint64 {
	return binary.BigEndian.Uint64(pub[:8])
}

func (pub PublicKey) ID128() string {
	return hex.EncodeToString(pub[:16])
}

func (pub PublicKey) Equal(p PublicKey) bool {
	return len(pub) == publicKeySize && bytes.Equal(pub, p)
}

func (pub PublicKey) Verify(message, signature []byte) bool {
	return len(pub) == publicKeySize &&
		len(signature) == signatureSize &&
		ed25519.Verify([]byte(pub), message, signature)
}

func DecodePublicKey(s string) PublicKey {
	s = strings.TrimPrefix(s, publicKeyEncodingPrefix)
	if p, _ := base64.StdEncoding.DecodeString(s); len(p) == publicKeySize {
		return p
	}
	return nil
}
