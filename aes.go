package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
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
func Encrypt(plainData string, passphrase string) (string, error) {
	data := []byte(plainData)

	block, err := aes.NewCipher([]byte(makeKey(passphrase)))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return stringify(ciphertext), nil
}

// Decrypt decrypts an AES block using a given passphrase.
func Decrypt(cipherData string, passphrase string) (string, error) {
	data := destringify(cipherData)

	key := []byte(makeKey(passphrase))

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ERROR: data is shorter than the nonce")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
