package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPublicKeyEncode(t *testing.T) {
	pub := NewPrivateKeyFromSeed("seed").PublicKey()

	assert(t, len(pub) == 32)
	assert(t, pub.Encode() == "Ed25519,8WXh5ffCkOUvLt7z+6tgy650v9MnT45e4d4zRclUoWY=")
}

func TestDecodePublicKey(t *testing.T) {
	prv := NewPrivateKeyFromSeed("seed")

	pub := DecodePublicKey("Ed25519,8WXh5ffCkOUvLt7z+6tgy650v9MnT45e4d4zRclUoWY=")

	assert(t, len(pub) == 32)
	assert(t, prv.PublicKey().Equal(pub))
}

func TestDecodePublicKey_fail(t *testing.T) {

	pub := DecodePublicKey("Ed25519,8WXh5ffCkOUvLt7z+6tgy650v9MnT45e4d4zRclUoWY1")

	assert(t, pub == nil)
}

func TestPrivateKey_Sign(t *testing.T) {
	prv := NewPrivateKeyFromSeed("seed")

	sig1 := prv.Sign([]byte("test-message"))
	sig2 := prv.Sign([]byte("test-message"))

	assert(t, len(sig1) == 64)
	assert(t, bytes.Equal(sig1, sig2))
}

func TestPublicKey_Verify(t *testing.T) {
	prv := NewPrivateKeyFromSeed("seed")
	pub := prv.PublicKey()

	sig := prv.Sign([]byte("test-message"))

	assert(t, pub.Verify([]byte("test-message"), sig)) // OK

	//--- fail
	assert(t, !pub.Verify([]byte("test-messagE"), sig)) // corrupted message
	sig[0]++
	assert(t, !pub.Verify([]byte("test-message"), sig)) // corrupted signature
}

func TestPublicKey_ID64(t *testing.T) {
	pub := NewPrivateKeyFromSeed("seed").PublicKey()
	pubHex := fmt.Sprintf("%x", []byte(pub))

	id64 := pub.ID64()

	assert(t, pubHex[:16] == fmt.Sprintf("%016x", id64))
}
