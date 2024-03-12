package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
)

type PrivateKey []byte

const SignatureSize = ed25519.SignatureSize

func NewPrivateKeyFromSeed(seed string) PrivateKey {
	return PrivateKey(ed25519.NewKeyFromSeed(Hash([]byte(seed))))
}

func (prv PrivateKey) String() string {
	return prv.Encode()
}

func (prv PrivateKey) Encode() string {
	return "PRIVATE:Ed25519," + base64.StdEncoding.EncodeToString(prv)
}

func (prv PrivateKey) SubKey(name string) PrivateKey {
	seed := Hash(prv, Hash([]byte(name)))
	return PrivateKey(ed25519.NewKeyFromSeed(seed))
}

func (prv PrivateKey) PublicKey() PublicKey {
	return PublicKey(ed25519.PrivateKey(prv).Public().(ed25519.PublicKey))
}

func (prv PrivateKey) Sign(message []byte) []byte {
	return ed25519.Sign([]byte(prv), message)
}
