package indifs

import (
	"encoding/hex"
	"encoding/json"
	"github.com/indifs/indifs/crypto"
	"testing"
)

var (
	testPrv = crypto.NewPrivateKeyFromSeed("private-key-seed")
	testPub = testPrv.PublicKey()

	testHeaders = []Header{{
		{"Ver", []byte("1")},
		{"Title", []byte("Hello, 世界")},
		{"Description", []byte("Test header")},
		{"Created", []byte("2022-01-01T01:02:03Z")},
		{"Updated", []byte("2022-01-01T01:02:03Z")},
		{"Part-Size", []byte("1024")},
	}, {
		{"Ver", []byte("1")},
		{"Path", []byte("/")},
	}, {
		{"Ver", []byte("1")},
		{"Path", []byte("/dir/")},
	}, {
		{"Ver", []byte("2")},
		{"Path", []byte("/dir/abc.txt")},
		{"Size", []byte("3")},
		{"Merkle", crypto.Hash([]byte("ABC"))},
	}}
)

func init() {
	testHeaders[0].Sign(testPrv)
}

const testHeadersJSON = `[{
	"Ver":"1",
	"Title":"b64,SGVsbG8sIOS4lueVjA",
	"Description":"Test header",
	"Created":"2022-01-01T01:02:03Z",
	"Updated":"2022-01-01T01:02:03Z",
	"Part-Size":"1024",
	"Public-Key":"Ed25519,pms+pTAx/wOs+rx9Gy4wbdMWR/iz6MkEUBGlPF121GU=",
	"Signature":"b64,Q4YmNXtV2avPrCl5r9cJfW1HVZWUQq781te2sdCgbdlW1ticCFMSwJeuEvGqpiZm7Xj6xq6Px0E7+V448HjBBA"
},{
	"Ver":"1",
	"Path":"/"
},{
	"Ver":"1",
	"Path":"/dir/"
},{
	"Ver":"2",
	"Path":"/dir/abc.txt",
	"Size":"3",
	"Merkle":"b64,tdQEXD9Gb6kf4sxqvnkjKhpXzfEE96JucW4KHieJ33g"
}]`

func TestValidateHeader(t *testing.T) {
	for _, h := range testHeaders {
		err := ValidateHeader(h)
		assert(t, err == nil)
	}
}

func BenchmarkHeader_Hash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		testHeaders[0].Hash()
	}
}

func TestHeader_String(t *testing.T) {
	assert(t, equalJSON(toJSON(testHeaders[0]), `{
		"Ver":         "1",
		"Title":       "b64,SGVsbG8sIOS4lueVjA",
		"Description": "Test header",
		"Created":     "2022-01-01T01:02:03Z",
		"Updated":     "2022-01-01T01:02:03Z",
		"Part-Size":   "1024",
		"Public-Key":  "Ed25519,pms+pTAx/wOs+rx9Gy4wbdMWR/iz6MkEUBGlPF121GU=",
		"Signature":   "b64,Q4YmNXtV2avPrCl5r9cJfW1HVZWUQq781te2sdCgbdlW1ticCFMSwJeuEvGqpiZm7Xj6xq6Px0E7+V448HjBBA"
	}`))
}

func TestHeader_MarshalJSON(t *testing.T) {
	assert(t, equalJSON(toJSON(testHeaders), testHeadersJSON))
}

func TestHeader_UnmarshalJSON(t *testing.T) {

	var hh []Header
	err := json.Unmarshal([]byte(testHeadersJSON), &hh)

	assert(t, err == nil)
	assert(t, equal(testHeaders, hh))
}

func TestHeader_Hash(t *testing.T) {

	h0 := testHeaders[0]
	hash := hex.EncodeToString(h0[:len(h0)-1].Hash())

	assert(t, hash == "436ba5c95f06a88236297e5733e89c758b3528753a592eeb305110f29821f7ab")
}

func TestHeader_Verify(t *testing.T) {
	assert(t, testHeaders[0].Verify())
}
