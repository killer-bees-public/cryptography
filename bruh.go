package main

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

const blockSize = 16

func symmetricEncrypt(data []byte, key []byte) ([]byte, error) {
	if len(key) != blockSize {
		return nil, fmt.Errorf("Incorrect key size")
	}
	cipher, err := aes.NewCipher(key)
	var encryptedData []byte
	cipher.Encrypt(encryptedData, data)

	return encryptedData, err
}

func symmetricDecrypt(encryptedData []byte, key []byte) ([]byte, error) {
	if len(key) != blockSize {
		return nil, fmt.Errorf("Incorrect key size")
	}
	cipher, err := aes.NewCipher(key)
	var decryptedData []byte
	cipher.Decrypt(decryptedData, encryptedData)

	return decryptedData, err
}

func createHMAC(data []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)

	return mac.Sum(nil)
}

func verifyHMAC(data []byte, tag []byte, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)

	return hmac.Equal(mac.Sum(nil), tag)
}

func main() {

	fmt.Printf("Whats good my fello friends")
}
