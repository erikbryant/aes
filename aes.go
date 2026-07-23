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

// base64encode encodes a []byte as a string.
func base64encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// base64decode decodes a string back into a []byte.
func base64decode(data string) ([]byte, error) {
	decode, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, fmt.Errorf("base64decode: %w", err)
	}

	return decode, nil
}

// deriveKey converts the input string to a 32-byte key for encryption.
func deriveKey(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))

	return hex.EncodeToString(hasher.Sum(nil))
}

// Encrypt performs AES encryption on data using a given passphrase.
func Encrypt(plainData string, passphrase string) (string, error) {
	data := []byte(plainData)

	block, err := aes.NewCipher([]byte(deriveKey(passphrase)))
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

	return base64encode(ciphertext), nil
}

// Decrypt decrypts an AES block using a given passphrase.
func Decrypt(cipherData string, passphrase string) (string, error) {
	data, err := base64decode(cipherData)
	if err != nil {
		return "", err
	}

	key := []byte(deriveKey(passphrase))

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
		return "", fmt.Errorf("ciphertext shorter than nonce")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
