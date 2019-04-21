package main

import (
	"flag"
	"fmt"
	"github.com/erikbryant/aes"
)

var (
	cipherText = flag.String("cipherText", "", "The text to decrypt")
	plainText  = flag.String("plainText", "", "The text to encrypt")
	passPhrase = flag.String("passPhrase", "", "The pass phrase to encrypt with")
)

func main() {
	flag.Parse()

	if *passPhrase == "" {
		fmt.Println("You must supply a pass phrase.")
		return
	}

	if *plainText == "" && *cipherText == "" {
		fmt.Println("You must supply either the plain text or the cipher text.")
		return
	}

	if *plainText != "" && *cipherText != "" {
		fmt.Println("You must supply either the plain text or the cipher text, but not both.")
		return
	}

	if *plainText != "" {
		ciphertext := aes.Encrypt(*plainText, *passPhrase)
		fmt.Println("Encrypted:", ciphertext)
		plaintext := aes.Decrypt(ciphertext, *passPhrase)
		fmt.Println("Decrypted:", plaintext)
		return
	}

	plaintext := aes.Decrypt(*cipherText, *passPhrase)
	fmt.Printf("Decrypted: %s\n", plaintext)
}
