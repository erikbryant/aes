# aes

AES encryption/decryption library

Based on the encryption article by [Nic Raboy](https://www.thepolyglotdeveloper.com/2018/02/encrypt-decrypt-data-golang-application-crypto-packages/).

## Usage

### Encrypt

```golang
plainText := "rattlesnake"
passphrase := "bites"

cipherText, err := Encrypt(plainText, passphrase)
if err != nil {
  return err
}
```

### Decrypt

```golang
cipherText := "vJ5fbgmTTPDc+ebBYbjaCq7JjOQWSy10T3JyC3wfF4Xp0UoEaq40"
passphrase := "bites"

plainText, err := aes.Decrypt(cipherText, passphrase)
if err != nil {
  return err
}
```
