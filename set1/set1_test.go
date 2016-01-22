package set1

import (
	"testing"
	"encoding/hex"
	"sort"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }
type MySuite struct{}
var _ = Suite(&MySuite{})

func (s *MySuite) TestBase64Encode(c *C) {
	c.Assert(Base64Encode([]byte{}), DeepEquals, []byte{})
	c.Assert(Base64Encode([]byte("1")), DeepEquals, []byte("MQ=="))
	c.Assert(Base64Encode([]byte("12")), DeepEquals, []byte("MTI="))
	c.Assert(Base64Encode([]byte("abc")), DeepEquals, []byte("YWJj"))
	c.Assert(Base64Encode([]byte("defg")), DeepEquals, []byte("ZGVmZw=="))
	input := []byte("I'm killing your brain like a poisonous mushroom")
	expected := []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3" + 
		"VzIG11c2hyb29t")
	c.Assert(Base64Encode(input), DeepEquals, expected)
}

func (s *MySuite) TestHextToBase64(c *C) {
	c.Assert(HexToBase64(""), Equals, "")
	input := ("49276d206b696c6c696e6720796f757220627261696e206c696b65206" +
			"120706f69736f6e6f7573206d757368726f6f6d")
	expected := ("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG" + 
			"11c2hyb29t")
	c.Assert(HexToBase64(input), Equals, expected)
}

func (s *MySuite) TestFixedXOR(c *C) {
	c.Assert(func() { FixedXOR([]byte{}, []byte{'a'}) }, PanicMatches,
		"Input strings must have the same length")
	c.Assert(FixedXOR([]byte{}, []byte{}), DeepEquals, []byte{})
	c.Assert(FixedXOR([]byte{'a', 0xa5, 0x0f}, []byte{'a', 0x5a, 0xff}),
			DeepEquals, []byte{0, 0xff, 0xf0})
	in1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	in2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	expected, _ := hex.DecodeString("746865206b696420646f6e277420706c6179")
	c.Assert(FixedXOR(in1, in2), DeepEquals, expected)
}

func (s *MySuite) TestcandidateByScoreDesc(c *C) {
	candidates := []candidate{}
	sort.Sort(ByScoreDesc(candidates))
	c.Assert(candidates, DeepEquals, []candidate{})

	a := candidate{1, 'x', []byte{'a'}}
	candidates = []candidate{a}
	sort.Sort(ByScoreDesc(candidates))
	c.Assert(candidates, DeepEquals, []candidate{a})

	b := candidate{2, 'y', []byte{'b'}}
	candidates = []candidate{a, b}
	sort.Sort(ByScoreDesc(candidates))
	c.Assert(candidates, DeepEquals, []candidate{b, a})
}

func (s *MySuite) TestDecrypt1ByteXOR(c *C) {
	input, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828" +
			"372d363c78373e783a393b3736")
	expected := []byte("Cooking MC's like a pound of bacon")
	c.Assert(Decrypt1ByteXOR(input).bytes, DeepEquals, expected)

	input = FixedXOR([]byte("English Text"), []byte("ZZZZZZZZZZZZ"))
	c.Assert(Decrypt1ByteXOR(input).bytes, DeepEquals, []byte("English Text"))
}

func (s *MySuite) TestRepeatingXOR(c *C) {
	c.Assert(func() { RepeatingXOR([]byte{}, []byte{}) }, PanicMatches, "Key must not be empty")
	c.Assert(func() { RepeatingXOR([]byte{'a'}, []byte{}) }, PanicMatches, "Key must not be empty")
	c.Assert(RepeatingXOR([]byte{}, []byte{'a'}), DeepEquals, []byte{})
	c.Assert(RepeatingXOR([]byte{'a'}, []byte{'a'}), DeepEquals, []byte{0x00})
	c.Assert(RepeatingXOR([]byte("abc"), []byte("xy")), DeepEquals, []byte{0x19, 0x1b, 0x1b})
}

func (s *MySuite) TestHammingDistance(c *C) {
	c.Assert(HammingDistance([]byte{}, []byte{}), Equals, 0)
	c.Assert(HammingDistance([]byte{0x07}, []byte{0x02}), Equals, 2)
	c.Assert(HammingDistance([]byte("abc"), []byte("abc")), Equals, 0)
	c.Assert(HammingDistance([]byte("abc"), []byte("ab")), Equals, 8)
	c.Assert(HammingDistance([]byte("this is a test"),
			[]byte("wokka wokka!!!")), Equals, 37)
}

func (s *MySuite) TestFindRepeatingXORKeySize(c *C) {
	c.Assert(func() { FindRepeatingXORKeySize([]byte{}, 1, 2, 2) },
		PanicMatches, ".*")
	c.Assert(func() { FindRepeatingXORKeySize([]byte("abcdef"), -1, 1, 2) },
		PanicMatches, ".*")
	c.Assert(func() { FindRepeatingXORKeySize([]byte("abcdef"), 2, 1, 2) },
		PanicMatches, ".*")
	c.Assert(func() { FindRepeatingXORKeySize([]byte("abcdef"), 2, 4, 2) },
		PanicMatches, ".*")

	// text from challenge 5 was XORed with a 3-byte key, but 28 is the best
	// key size by this method
	input, _ := hex.DecodeString(
		"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242" +
		"72765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028316528" +
		"6326302e27282f")
	c.Assert(FindRepeatingXORKeySize(input, 1, 35, 10), Equals, 28)
}

func (s *MySuite) TestFindRepeatingXORKey(c *C) {
	c.Assert(func() { FindRepeatingXORKey([]byte{}, 1) }, PanicMatches, ".*")

	input, _ := hex.DecodeString(
		"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263242" +
		"72765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028316528" +
		"6326302e27282f")
	c.Assert(FindRepeatingXORKey(input, 3), DeepEquals, []byte("ICE"))
}
