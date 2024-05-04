package crypto

import "testing"

func BenchmarkPublicKey_Verify(b *testing.B) {
	prv := NewPrivateKeyFromSeed("seed")
	pub := prv.PublicKey()
	sig := prv.Sign([]byte("test-message"))

	for i := 0; i < b.N; i++ {
		assert(nil, pub.Verify([]byte("test-message"), sig)) // OK
	}
}

func BenchmarkPublicKey_DecodePublicKeyAndVerify(b *testing.B) {
	prv := NewPrivateKeyFromSeed("seed")
	pub := prv.PublicKey()
	sPub := pub.Encode()
	sig := prv.Sign([]byte("test-message"))

	for i := 0; i < b.N; i++ {
		pub2 := DecodePublicKey(sPub)
		assert(nil, pub2 != nil)
		assert(nil, pub2.Verify([]byte("test-message"), sig)) // OK
	}
}

func assert(t *testing.T, ok bool) {
	if !ok {
		t.Fatal("assertion failed")
	}
}
