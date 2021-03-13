package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
)

// Encrypt encrypts the plain text data
func Encrypt(secret []byte, plainTextData []byte) (EncryptedData []byte, err error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	EncryptedData = aesgcm.Seal(nil, nonce, plainTextData, nil)
	EncryptedData = append(EncryptedData, nonce...)
	return EncryptedData, nil
}

// Decrypt decrypts the plain text data
func Decrypt(secret []byte, encryptedData []byte) (plainText []byte, err error) {
	nonce := encryptedData[len(encryptedData)-12:]
	encryptedData = encryptedData[:len(encryptedData)-12]
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
