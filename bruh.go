package main

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
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

// ////////////////    ECDSA    //////////////////
// Utilizing ECDSA to sign and verify delivery of an AES key
func createKeyPair() (*ecdsa.PrivateKey, crypto.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Errorf("Something went wrong with generating a private key")
	}

	return privateKey, privateKey.Public()
}

func sign(priv *ecdsa.PrivateKey, message []byte) ([]byte, error) {
	var arr = sha256.Sum256(message)
	slice := arr[:]
	asn1, err := ecdsa.SignASN1(rand.Reader, priv, slice)

	return asn1, err
}

func verify(pub *ecdsa.PublicKey, message []byte, sig []byte) bool {
	var arr = sha256.Sum256(message)
	slice := arr[:]
	return ecdsa.VerifyASN1(pub, slice, sig)
}

//////////////////     END     //////////////////

func main() {

	fmt.Printf("Whats good my fello friends")
}
