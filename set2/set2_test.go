package set2

import (
	. "gopkg.in/check.v1"
	"matasano-crypto-challenge-solutions-go/set1"
	"testing"
	"math/rand"
)

func Test(t *testing.T) { TestingT(t) }

type MySuite struct{}

var _ = Suite(&MySuite{})

func (s *MySuite) TestPkcs7Pad(c *C) {
	c.Assert(func() { Pkcs7Pad([]byte{}, 0) }, PanicMatches,
		"Block size must be positive")
	c.Assert(Pkcs7Pad([]byte{}, 1), DeepEquals, []byte{1})
	c.Assert(Pkcs7Pad([]byte("abc"), 1), DeepEquals, []byte("abc\x01"))
	c.Assert(Pkcs7Pad([]byte("abc"), 2), DeepEquals, []byte("abc\x01"))
	c.Assert(Pkcs7Pad([]byte("abc"), 3), DeepEquals, []byte("abc\x03\x03\x03"))
	c.Assert(Pkcs7Pad([]byte("abc"), 4), DeepEquals, []byte("abc\x01"))
	c.Assert(Pkcs7Pad([]byte("abc"), 5), DeepEquals, []byte("abc\x02\x02"))

	// 255 padding bytes: allowed
	textWithLongestPadding := Pkcs7Pad([]byte("abc"), 258)
	c.Assert(len(textWithLongestPadding), Equals, 258)
	c.Assert(textWithLongestPadding[:4], DeepEquals, []byte("abc\xff"))
	c.Assert(textWithLongestPadding[257], Equals, byte(255))

	// 256 padding bytes: too long
	c.Assert(func() { Pkcs7Pad([]byte("abc"), 259) }, PanicMatches,
		"Padding bytes can't exceed 255")
}

func (s *MySuite) TestPkcs7Unpad(c *C) {
	c.Assert(func() { Pkcs7Unpad([]byte{}) }, PanicMatches, ".*")
	c.Assert(Pkcs7Unpad([]byte{1}), DeepEquals, []byte{})
	c.Assert(Pkcs7Unpad([]byte{2, 2}), DeepEquals, []byte{})
	c.Assert(Pkcs7Unpad([]byte("This is a test\x03\x03\x03")), DeepEquals,
		[]byte("This is a test"))

	// bytes that are supposed to be padding don't match
	c.Assert(func() { Pkcs7Unpad([]byte("This is a test\x04\x04\x04")) },
		PanicMatches, ".*")

	// more padding bytes than total length
	c.Assert(func() { Pkcs7Unpad([]byte("This is a test\x10")) },
		PanicMatches, ".*")
}
func (s *MySuite) TestEncryptAes128Ecb(c *C) {
	key := []byte("YELLOW SUBMARINE")
	text := []byte("This is a test!!")

	// key length be at least 16
	c.Assert(func() { EncryptAes128EcbWholeBlocks([]byte(text), key[:15]) },
		PanicMatches, ".*")

	// input length must be whole number of blocks
	c.Assert(func() { EncryptAes128EcbWholeBlocks(text[:15], key) },
		PanicMatches, ".*")
	c.Assert(func() { EncryptAes128EcbWholeBlocks(append(text, byte(1)), key) },
		PanicMatches, ".*")

	c.Assert(EncryptAes128EcbWholeBlocks([]byte{}, key), DeepEquals, []byte{})
	doubleText := append(text, text...)
	c.Assert(set1.DecryptAes128Ecb(EncryptAes128EcbWholeBlocks(doubleText, key), key),
		DeepEquals, doubleText)
}

func (s *MySuite) TestEncryptDecryptAes128Cbc(c *C) {
	key := []byte("YELLOW SUBMARINE")

	// ciphertext too short to be valid
	c.Assert(func() { DecryptAes128Cbc([]byte("a"), key, ZeroIV) },
		PanicMatches, ".*")

	// IV wrong length
	c.Assert(func() { DecryptAes128Cbc(EncryptAes128Cbc([]byte("a"), key, ZeroIV),
		key, ZeroIV[:15]) }, PanicMatches, ".*")
	c.Assert(func() { DecryptAes128Cbc(EncryptAes128Cbc([]byte("a"), key, ZeroIV[:15]),
		key, ZeroIV) }, PanicMatches, ".*")

	examples := [][]byte{
		[]byte{},
		[]byte("a"),
		[]byte("This is a test"),
		[]byte("This is a longer test")}
	for _, text := range examples {
		c.Assert(DecryptAes128Cbc(EncryptAes128Cbc(text, key, ZeroIV),
			key, ZeroIV), DeepEquals, text)
	}
}

func (s *MySuite) TestDetectMode(c *C) {
	r := *rand.New(rand.NewSource(1))
	encrypt := func (input []byte) ([]byte, string) {
		return EncryptionOracle(input, r)}
	for i := 0; i < 1000; i++ {
		detectedMode, actualMode := DetectMode(encrypt)
		c.Assert(actualMode, Equals, detectedMode)
	}
}

func (s *MySuite) TestParseKeyValuePairs(c *C) {
	m, err := ParseKeyValuePairs("a=b")
	c.Assert(m, DeepEquals, map[string]string{"a": "b"})
	c.Assert(err, IsNil)

	m, err = ParseKeyValuePairs("a=b&c=d")
	c.Assert(m, DeepEquals, map[string]string{"a": "b", "c": "d"})
	c.Assert(err, IsNil)

	m, err = ParseKeyValuePairs("foo=bar&baz=qux&zap=zazzle")
	c.Assert(m, DeepEquals, map[string]string{"foo": "bar", "baz": "qux", "zap": "zazzle"})
	c.Assert(err, IsNil)

	errorStrings := []string{ "", "&", "&&", "&=", "&a=b", "a=b&"}
	for _, s := range errorStrings {
		m, err := ParseKeyValuePairs(s)
		c.Assert(m, DeepEquals, map[string]string(nil))
		c.Assert(err, ErrorMatches, ".*")
	}
}

func (s *MySuite) TestProfileFor(c *C) {
	c.Assert(ProfileFor("foo@bar.com"), Equals, "email=foo@bar.com&uid=10&role=user")
	c.Assert(ProfileFor("foobar"), Equals, "email=foobar&uid=10&role=user")
	c.Assert(func() { ProfileFor("foo=bar") }, PanicMatches, ".*")
	c.Assert(func() { ProfileFor("foo&bar") }, PanicMatches, ".*")
}
