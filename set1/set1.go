package set1

import (
	"bytes"
	"encoding/hex"
	"encoding/base64"
	"math"
	"fmt"
	"strings"
	"sort"
	"bufio"
	"os"
	"io/ioutil"
	"crypto/aes"
)

// Symbols used in Base64
const base64Symbols string = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz0123456789+/")

// Base64Encode returns a Base64-encoded version of the given byte array.
func Base64Encode(s []byte) []byte {
	length := len(s)
	// output always takes ceil(length * 4/3) bytes because padding symbols are
	// added
	result := make([]byte, 0, int(math.Ceil(float64(length) * 4 / 3)))
	wholeBlockLength := length / 3 * 3
	var i int
	for i = 0; i < wholeBlockLength; i += 3 {
		// 1st symbol is bits 1-6 of 1st byte
		// 2nd symbol is bits 7-8 of 1st byte + bits 1-4 of 2nd byte
		// 3rd symbol is bits 5-8 of 2nd byte + bits 1-2 of 3rd byte
		// 4th symbol is bits 3-8 of 3rd byte
		result = append(result,
				base64Symbols[s[i] & 0xfc >> 2],
				base64Symbols[s[i] & 0x03 << 4 | s[i + 1] & 0xf0 >> 4],
				base64Symbols[s[i + 1] & 0x0f << 2 | s[i + 2] & 0xc0 >> 6],
				base64Symbols[s[i + 2] & 0x3f])
	}

	// last 1 or 2 bytes + padding
	if length != wholeBlockLength {
		// both cases have the first 6 bits and last 2 bits of leftover byte 1
		result = append(result, base64Symbols[s[i] & 0xfc >> 2])
		byte1End := s[i] & 0x03 << 4
		if length - wholeBlockLength == 1 {
			// 1 leftover byte: rest of 2nd symbol is 0. 2 padding symbols.
			result = append(result, base64Symbols[byte1End], '=', '=')
		} else if length - wholeBlockLength == 2 {
			// 2 leftover bytes: 2nd symbol also includes first 4 bits of byte
			// 2. 1 padding symbol.
			result = append(result, base64Symbols[byte1End | s[i + 1] & 0xf0 >> 4],
				base64Symbols[s[i + 1] & 0x0f << 2], '=')
		}
	}
	return result
}

// HexToBase64 takes a hexadecimal-encoded string and returns a
// Base64-encoded version of the bytes it represents.
func HexToBase64(hexStr string) string {
	bytearray, err := hex.DecodeString(hexStr)
	if err != nil {
		panic(err)
	}
	return string(Base64Encode(bytearray))
}

// FixedXOR returns the XOR of two equal-length byte arrays.
func FixedXOR(s1, s2 []byte) []byte {
	if len(s1) != len(s2) {
		panic("Input strings must have the same length")
	}
	result := make([]byte, len(s1))
	for i := range s1 {
		result[i] = s1[i] ^ s2[i]
	}
	return result
}

// Frequency of characters in English text.
var letterFrequency = map[byte]float64 {
	// made-up value for space, because that occurs much more frequently in
	// English text than in random bytes. (could also include punctuation.)
	' ': 20.0,
    'e': 12.02,
    't': 9.10,
    'a': 8.12,
    'o': 7.68,
    'i': 7.31,
    'n': 6.95,
    's': 6.28,
    'r': 6.02,
    'h': 5.92,
    'd': 4.32,
    'l': 3.98,
    'u': 2.88,
    'c': 2.71,
    'm': 2.61,
    'f': 2.30,
    'y': 2.11,
    'w': 2.09,
    'g': 2.03,
    'p': 1.82,
    'b': 1.49,
    'v': 1.11,
    'k': 0.69,
    'x': 0.17,
    'q': 0.11,
    'j': 0.10,
    'z': 0.07,
}

// Score returns a score for how likely the given byte array is to be English
// text.
func Score(s []byte) float64 {
	var sum float64 = 0
	for _, c := range(s) {
		c = strings.ToLower(string(c))[0]
		if val, ok := letterFrequency[c]; ok {
			sum += val
		}
	}
	return sum / float64(len(s))
}

// candidate represents a possible decryption of a string.
type candidate struct {
	score float64
	key byte
	bytes []byte
}
func (c candidate) String() string {
	return fmt.Sprintf("%f: %q %q", c.score, c.key, string(c.bytes))
}

// ByScoreDesc provides a way to sort candidates with the highest-scoring one
// first.
type ByScoreDesc []candidate
func (a ByScoreDesc) Len() int {
	return len(a)
}
func (a ByScoreDesc) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}
func (a ByScoreDesc) Less(i, j int) bool {
	return a[i].score > a[j].score
}

// Decrypt1ByteXOR returns a candidate representing the most likely decryption
// of the input if it was "encrypted" by XORing every byte with the same byte.
// Input should not be empty.
func Decrypt1ByteXOR(input []byte) candidate {
	var candidates []candidate
	for key := 0; key < 256; key++ {
		keyStr := []byte(strings.Repeat(string([]byte{byte(key)}), len(input)))
		output := FixedXOR(keyStr, input)
		score := Score(output)
		candidates = append(candidates, candidate{score, byte(key), output})
	}
	sort.Sort(ByScoreDesc(candidates))
	return candidates[0]
}

// RepeatingXOR "encrypts" or "decrypts" the input by XORING each byte of it
// with the corresponding byte of the key, repeating when the end of the key
// is reached.
func RepeatingXOR(input []byte, key []byte) []byte {
	if len(key) == 0 {
		panic("Key must not be empty")
	}
	output := make([]byte, 0, len(input))
	for i, c := range input {
		keyByte := key[i % len(key)]
		output = append(output, c ^ keyByte)
	}
	return output
}

// HammingDistance returns the number of differing bits between two byte
// slices.
func HammingDistance(a []byte, b []byte) int {
	// let 'a' be the shorter string
	if len(a) > len(b) {
		b, a = a, b
	}
	sum := 0
	for i := range a {
		for mask := 1; mask <= 0x80; mask <<= 1 {
			if a[i] & byte(mask) != b[i] & byte(mask) {
				sum++
			}
		}
	}
	// extra bits in the longer string are considered "different"
	sum += 8 * (len(b) - len(a))
	return sum
}

// FindRepeatingXORKeySize returns the most likely key size that was used to
// "encrypt" the input using repeating XOR. numBlocks gives the number of
// blocks of input to look at for each possible key size (if input is long
// enough, otherwise as many blocks as possible will be used).
func FindRepeatingXORKeySize(input []byte, minKeySize int, maxKeySize int,
		numBlocks int) (bestKeySize int) {
	if len(input) == 0 {
		panic("Input must not be empty")
	}
	if minKeySize < 0 {
		panic("Key size must be positive")
	}
	if minKeySize >= maxKeySize {
		panic("Max key size must exceed min")
	}
	if maxKeySize > len(input) / 2 {
		panic(fmt.Sprintf("Input too short for multiple blocks of %d bytes",
			maxKeySize))
	}
	var bestNormalizedDistance float64 = math.Inf(1)
	for keySize := minKeySize; keySize <= maxKeySize; keySize++ {
		// numBlocks can only go up to floor(length / key size) in order to fit
		// all the blocks.
		maxBlocks := len(input) / keySize
		if numBlocks > maxBlocks {
			numBlocks = maxBlocks
		}
		sum := 0.
		for i := 0; i < numBlocks - 1; i++ {
			block1 := input[keySize * i : keySize * (i + 1)]
			block2 := input[keySize * (i + 1) : keySize * (i + 2)]
			distance := (float64(HammingDistance(block1, block2)) /
					float64(keySize))
			sum += distance
		}
		normalizedDistance := sum / float64(numBlocks)
		if normalizedDistance < bestNormalizedDistance {
			bestKeySize = keySize
			bestNormalizedDistance = normalizedDistance
		}
	}
	return bestKeySize
}

// FindRepeatingXORKey returns the key used to encrypt the input with
// repeating XOR, given the key size.
func FindRepeatingXORKey(input []byte, keySize int) []byte {
	numBlocks := int(math.Ceil(float64(len(input)) / float64(keySize)))
	if numBlocks == 0 {
		panic("Input is too short relative to key")
	}
	theKey := make([]byte, keySize)
	// loop over byte index within blocks
	for i := 0; i < keySize; i++ {
		sameKeyBytes := make([]byte, numBlocks, numBlocks)
		// loop over blocks
		for j := 0; j < numBlocks; j++ {
			offset := j * keySize + i
			if offset >= len(input) {
				break
			}
			sameKeyBytes[j] = input[offset]
		}
		candidate := Decrypt1ByteXOR(sameKeyBytes)
		theKey[i] = candidate.key
	}
	return theKey
}

// DecryptAes128Ecb decrypts the input using the given key using AES-128 in
// ECB mode. (the standard library left out ECB mode because it's insecure.)
func DecryptAes128Ecb(input []byte, key []byte) []byte {
	if len(key) == 0 {
		panic("Key must not be empty")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	size := block.BlockSize()
	plaintext := make([]byte, len(input))
	for i := 0; i < len(input); i+= size {
		inputBlock := input[i : i + size]
		dst := make([]byte, size)
		block.Decrypt(dst, inputBlock)
		plaintext = append(plaintext, dst...)
	}
	return plaintext
}

// findRepeatedBlocks searches the input for repeated blocks of the given size,
// and returns a slice of pairs of indices of blocks that were repeated.
func findRepeatedBlocks(input []byte, blockSize int) (repeatIndices [][]int) {
	// round down because any partial blocks are not repeated
	numBlocks := len(input) / blockSize
	for i := 0; i < numBlocks; i++ {
		for j := i + 1; j < numBlocks; j++ {
			block1 := input[i * blockSize : (i + 1) * blockSize]
			block2 := input[j * blockSize : (j + 1) * blockSize]
			if bytes.Compare(block1, block2) == 0 {
				repeatIndices = append(repeatIndices, []int{i, j})
			}
		}
	}
	return
}

func Challenge1() {
	fmt.Println("\nSet 1 challenge 1\n=================")
	hexStr := ("49276d206b696c6c696e6720796f757220627261696e206c696b65206" +
			"120706f69736f6e6f7573206d757368726f6f6d")
	fmt.Println(HexToBase64(hexStr))
}

func Challenge2() {
	fmt.Println("\nSet 1 challenge 2\n=================")
	str1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	str2, _ := hex.DecodeString("686974207468652062756c6c277320657965")
	fmt.Printf("%x\n", string(FixedXOR(str1, str2)))
}

func Challenge3() {
	fmt.Println("\nSet 1 challenge 3\n=================")
	input, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828" +
			"372d363c78373e783a393b3736")
	result := Decrypt1ByteXOR(input)
	fmt.Printf("The key is: %q (0x%x)\n", result.key, result.key)
	fmt.Println(string(result.bytes))
}

func Challenge4() {
	fmt.Println("\nSet 1 challenge 4\n=================")
	file, _ := os.Open("4.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var candidates []candidate
	for scanner.Scan() {
		line := scanner.Text()
		bytes, _ := hex.DecodeString(line)
		candidate := Decrypt1ByteXOR(bytes)
		candidates = append(candidates, candidate)
	}
	sort.Sort(ByScoreDesc(candidates))
	fmt.Printf("The key is: %q (0x%x)\n", candidates[0].key, candidates[0].key)
	fmt.Print(string(candidates[0].bytes))
}

func Challenge5() {
	fmt.Println("\nSet 1 challenge 5\n=================")
	s := []byte("Burning 'em, if you ain't quick and nimble\n" +
	"I go crazy when I hear a cymbal")
	e := RepeatingXOR(s, []byte("ICE"))
	fmt.Printf("%s\n", hex.EncodeToString(e))
}

func Challenge6() {
	fmt.Println("\nSet 1 challenge 6\n=================")
	text, _ := ioutil.ReadFile("6.txt")
	// using built-in base64 library to decode because only encoding was
	// included in challenge 1
	input, _ := base64.StdEncoding.DecodeString(string(text))
	keySize := FindRepeatingXORKeySize(input, 2, 40, 10)
	fmt.Println("Key size:", keySize)
	key := FindRepeatingXORKey(input, keySize)
	fmt.Printf("The key is: \"%s\"\n\n", string(key))
	fmt.Println(string(RepeatingXOR(input, key)))
}

func Challenge7() {
	fmt.Println("\nSet 1 challenge 7\n=================")
	text, _ := ioutil.ReadFile("7.txt")
	ciphertext, _ := base64.StdEncoding.DecodeString(string(text))
	plaintext := DecryptAes128Ecb(ciphertext, []byte("YELLOW SUBMARINE"))
	fmt.Println(string(plaintext))
}

func Challenge8() {
	fmt.Println("\nSet 1 challenge 8\n=================")
	file, _ := os.Open("8.txt")
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	/* since identical plaintext blocks produce identical encrypted blocks, if
	* any of the lines repeats the same block, it's probably text encrypted in
	* ECB mode and not just random. identical blocks of 16 bytes probably
	* don't happen happen a lot in real text but it's still are more likely
	* than in random data.
	*/
	for i := 1; scanner.Scan(); i++ {
		line := scanner.Text()
		ciphertext, _ := base64.StdEncoding.DecodeString(line)
		repeatIndices := findRepeatedBlocks(ciphertext, 16)
		if repeatIndices != nil {
			fmt.Println("Line", i, "has matching blocks:", repeatIndices)
		}
	}
}
