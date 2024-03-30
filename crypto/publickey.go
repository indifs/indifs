package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
)

type PublicKey []byte

const PublicKeySize = ed25519.PublicKeySize

const publicKeyEncodingPrefix = "Ed25519,"

func (pub PublicKey) String() string {
	return pub.Encode()
}

func (pub PublicKey) Encode() string {
	return publicKeyEncodingPrefix + base64.StdEncoding.EncodeToString(pub)
}

func (pub PublicKey) Equal(p PublicKey) bool {
	return len(pub) == PublicKeySize && bytes.Equal(pub, p)
}

func (pub PublicKey) Verify(message, signature []byte) bool {
	return len(pub) == PublicKeySize &&
		len(signature) == SignatureSize &&
		ed25519.Verify([]byte(pub), message, signature)
}

func DecodePublicKey(s string) PublicKey {
	s = strings.TrimPrefix(s, publicKeyEncodingPrefix)
	if p, _ := base64.StdEncoding.DecodeString(s); len(p) == PublicKeySize {
		return p
	}
	return nil
}
