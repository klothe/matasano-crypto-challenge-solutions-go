package set2

import (
	"crypto/aes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"matasano-crypto-challenge-solutions-go/set1"
	"math/rand"
)

// all-0 initialization vector for AES-128 in CBC mode
var ZeroIV = make([]byte, aes.BlockSize)

// Pkcs7Pad returns the input with padding appended up to blockSize bytes
// according to PKCS#7. see https://tools.ietf.org/html/rfc5652#section-6.3
func Pkcs7Pad(input []byte, blockSize int) []byte {
	if blockSize <= 0 {
		panic("Block size must be positive")
	}
	// if the input is a whole number of blocks, it gets padded with an
	// extra block so there are always some padding bytes.
	padding_bytes := blockSize - len(input)%blockSize
	if padding_bytes > 0xff {
		panic("Padding bytes can't exceed 255")
	}
	for i := 0; i < padding_bytes; i++ {
		input = append(input, byte(padding_bytes))
	}
	return input
}

// Pkcs7Pad returns a slice of the input with padding removed, assuming it was
// padded according to PKCS#7.
func Pkcs7Unpad(input []byte) []byte {
	if len(input) == 0 {
		panic("Empty string is not valid PKCS#7")
	}
	lastByte := int(input[len(input)-1])
	if lastByte > len(input) {
		panic(fmt.Sprintf("Malformed input: length %d with %d padding bytes",
			len(input), lastByte))
	}
	// make sure all the padding bytes match
	paddingStart := len(input) - lastByte
	for i := paddingStart; i < len(input)-1; i++ {
		if int(input[i]) != lastByte {
			panic(fmt.Sprintf("Malformed input: padding byte %d != %d",
				input[i], lastByte))
		}
	}
	return input[:paddingStart]
}

// EncryptAes128Ecb encrypts the input with the given key using AES-128 in
// ECB mode. No padding is used, so the input must be a whole number of blocks.
func EncryptAes128EcbWholeBlocks(input []byte, key []byte) []byte {
	// NewCipher will complain here if the key is too short
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	size := block.BlockSize()
	if len(input)%size != 0 {
		panic(fmt.Sprintf("Input length %d is not a multiple of block size %d",
			len(input), size))
	}
	output := []byte{}
	for i := 0; i < len(input); i += size {
		dst := make([]byte, size)
		block.Encrypt(dst, input[i:i+size])
		output = append(output, dst...)
	}
	return output
}

// EncryptAes128Cbc encrypts the input using AES-128 in ECB mode, with
// the given key and initialization vector, using PKCS#7 padding.
func EncryptAes128Ecb(input []byte, key []byte) []byte {
	input = Pkcs7Pad(input, aes.BlockSize)
	return EncryptAes128EcbWholeBlocks(input, key)
}

// EncryptAes128Cbc encrypts the input using AES-128 in CBC mode, with
// the given key and initialization vector, using PKCS#7 padding.
func EncryptAes128Cbc(input []byte, key []byte, iv []byte) []byte {
	if len(iv) != aes.BlockSize {
		panic(fmt.Sprintf("IV length must be %d", aes.BlockSize))
	}
	input = Pkcs7Pad(input, aes.BlockSize)
	output := make([]byte, 0, len(input))
	prevBlock := iv
	for i := 0; i < len(input); i += aes.BlockSize {
		// XOR with previous block before encrypting
		inputBlock := input[i : i+aes.BlockSize]
		encryptedBlock := set1.FixedXOR(prevBlock, inputBlock)
		encryptedBlock = EncryptAes128EcbWholeBlocks(encryptedBlock, key)
		output = append(output, encryptedBlock...)
		prevBlock = encryptedBlock
	}
	return output
}

// DecryptAes128Cbc decrypts the input using AES-128 in ECB mode, with
// the given key and initialization vector, assuming it was padded
// according to PKCS#7.
func DecryptAes128Cbc(input []byte, key []byte, iv []byte) []byte {
	output := make([]byte, 0, len(input))
	prevBlock := iv
	for i := 0; i < len(input); i += aes.BlockSize {
		// XOR with previous block (or IV) after decrypting
		inputBlock := input[i : i+aes.BlockSize]
		decryptedBlock := set1.DecryptAes128Ecb(inputBlock, key)
		for i := 0; i < len(decryptedBlock); i++ {
			decryptedBlock[i] ^= prevBlock[i]
		}
		output = append(output, decryptedBlock...)
		prevBlock = inputBlock
	}
	return Pkcs7Unpad(output)
}

// encryptRandom encrypts the input, with 5-10 random bytes added
// before and after it, under a random key. If mode is "ECB", ECB mode
// is used; otherwise CBC mode is used with a random initialization vector.
func encryptRandom(input []byte, mode string, r rand.Rand) ([]byte) {
	// start with 5-10 random bytes, then append the input, then 5-10
	// more random bytes
	s := make([]byte, 5 + r.Intn(6))
	r.Read(s)
	s = append(s, input...)
	end := make([]byte, 5 + r.Intn(6))
	r.Read(end)
	s = append(s, end...)

	// random key
	key := make([]byte, 16)
	r.Read(key)

	if mode == "ECB" {
		return EncryptAes128Ecb(s, key)
	}

	// CBC mode with random IV
	iv := make([]byte, 16)
	r.Read(iv)
	return EncryptAes128Cbc(s, key, iv)
}

// EncryptionOracle encrypts the input, with 5-10 random bytes added before and
// after it, under a random key. It randomly chooses either ECB mode or CBC mode
// with a random initialization vector, and returns either "ECB" or "CBC"
// (for checking detection of the mode).
func EncryptionOracle(input []byte, r rand.Rand) ([]byte, string) {
	var mode string
	if r.Intn(2) == 0 {
		mode = "ECB"
	} else {
		mode = "CBC"
	}
	return encryptRandom(input, mode, r), mode
}

// DetectMode determines whether the given function encrypts its input in ECB
// mode or in CBC mode. Returns the detected mode and the actual mode, which
// should be the same (either "ECB" or "CBC").
func DetectMode(encrypt func([]byte, rand.Rand)([]byte, string),
		r rand.Rand) (detectedMode string, actualMode string) {
	/* in ECB mode, identical input blocks stay identical after being
	encrypted, but in CBC mode that's unlikely. with 5-10 random bytes at
	the beginning and 5-10 random bytes plus up to 16 bytes of padding at
	the end, only the 1st block and last 2 blocks are affected, so if you
	encrypt at least 5 blocks of all identical bytes, the 2nd and 3rd blocks
	will be still be identical after random bytes and padding. if these
	blocks match in the ciphertext, it's ECB. (you could check more than 2
	blocks to be extra sure.)
	*/
	input := make([]byte, 80)
	ciphertext, actualMode := encrypt(input, r)
	block2 := ciphertext[16:32]
	block3 := ciphertext[32:48]
	if string(block2) == string(block3) {
		detectedMode = "ECB"
	} else {
		detectedMode = "CBC"
	}
	return detectedMode, actualMode
}

func Challenge9() {
	fmt.Println("\nSet 2 challenge 9\n=================")
	s := Pkcs7Pad([]byte("YELLOW SUBMARINE"), 20)
	fmt.Printf("%q\n", s)
}

func Challenge10() {
	fmt.Println("\nSet 2 challenge 10\n==================")
	text, _ := ioutil.ReadFile("set2/10.txt")
	decodedText, _ := base64.StdEncoding.DecodeString(string(text))
	fmt.Printf("%s\n", string(DecryptAes128Cbc(decodedText,
		[]byte("YELLOW SUBMARINE"), ZeroIV)))
}

func Challenge11() {
	fmt.Println("\nSet 2 challenge 11\n==================")
	r := *rand.New(rand.NewSource(1))
	count := 100
	for i := 0; i < count; i++ {
		detectedMode, actualMode := DetectMode(EncryptionOracle, r)
		if detectedMode != actualMode {
			panic(fmt.Sprintf("Detected mode %s, actual %s\n",
				detectedMode, actualMode))
		}
	}
	fmt.Printf("Detected mode %d times\n", count)
}
