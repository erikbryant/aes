package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"io"
)

var (
	cipherText = flag.String("cipherText", "", "The text to decrypt")
	plainText  = flag.String("plainText", "", "The text to encrypt")
	passPhrase = flag.String("passPhrase", "", "The pass phrase to encrypt with")
)

// stringify encodes a []byte as a string.
func stringify(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// destringify decodes a string back into a []byte.
func destringify(data string) []byte {
	base64Dec, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		panic(err.Error())
	}
	return base64Dec
}

// makeKey converts the input string to a 32-byte key for encryption.
func makeKey(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Encrypt performs AES encryption on data using a given passphrase.
func Encrypt(plainData string, passphrase string) string {
	data := []byte(plainData)
	block, _ := aes.NewCipher([]byte(makeKey(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return stringify(ciphertext)
}

// Decrypt decrypts an AES block using a given passphrase.
func Decrypt(cipherData string, passphrase string) string {
	data := destringify(cipherData)
	key := []byte(makeKey(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}
	return string(plaintext)
}

// func main() {
// 	flag.Parse()
// 
// 	if *passPhrase == "" {
// 		fmt.Println("You must supply a pass phrase.")
// 		return
// 	}
// 
// 	if *plainText == "" && *cipherText == "" {
// 		fmt.Println("You must supply either the plain text or the cipher text.")
// 		return
// 	}
// 
// 	if *plainText != "" && *cipherText != "" {
// 		fmt.Println("You must supply either the plain text or the cipher text, but not both.")
// 		return
// 	}
// 
// 	if *plainText != "" {
// 		ciphertext := Encrypt(*plainText, *passPhrase)
// 		fmt.Println("Encrypted:", ciphertext)
// 		plaintext := Decrypt(ciphertext, *passPhrase)
// 		fmt.Println("Decrypted:", plaintext)
// 		return
// 	}
// 
// 	plaintext := Decrypt(*cipherText, *passPhrase)
// 	fmt.Printf("Decrypted: %s\n", plaintext)
// }
