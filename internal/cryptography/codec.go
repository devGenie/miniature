package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
)

// Encrypt encrypts the plain text data
func Encrypt(secret []byte, plainTextData []byte) (EncryptedData []byte, nonce []byte, err error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		log.Println(err)
		return nil, nil, err
	}

	nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	EncryptedData = aesgcm.Seal(nil, nonce, plainTextData, nil)
	return EncryptedData, nonce, nil
}

// Decrypt decrypts the plain text data
func Decrypt(secret []byte, nonce []byte, encryptedData []byte) (plainText []byte, err error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainText, err = aesgcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return nil, err
	}
	return plainText, nil
}
