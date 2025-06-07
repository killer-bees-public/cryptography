package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
)

const blockSize = 16

func symmetricEncrypt(data []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != blockSize {
		return nil, fmt.Errorf("Incorrect key size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf(err.Error())
	}

	ctr := cipher.NewCTR(block, nonce)

	encryptedData := make([]byte, len(data))
	ctr.XORKeyStream(encryptedData, data)

	return encryptedData, err
}

func symmetricDecrypt(encryptedData []byte, key []byte, nonce []byte) ([]byte, error) {
	if len(key) != blockSize {
		return nil, fmt.Errorf("Incorrect key size")
	}
	block, err := aes.NewCipher(key)

	ctr := cipher.NewCTR(block, nonce)

	decryptedData := make([]byte, len(encryptedData))
	ctr.XORKeyStream(decryptedData, encryptedData)
	return decryptedData, err
}

func testSymmetric() {
	secretMessage := "KillerBeesKnees1KillerBeesKnees1"
	//                123 123 123 132
	fmt.Printf("Here is the message: " + secretMessage + "\n")
	byteslice := []byte(secretMessage)

	symKey := "i6Bwnnu8jbUbw1Mo"
	//         123 123 123 123
	keyBytes := []byte(symKey)

	nonce := make([]byte, len(symKey))
	rand.Read(nonce)

	encryptedMessage, err := symmetricEncrypt(byteslice, keyBytes, nonce)
	if err != nil {
		log.Fatal("Error: %v", err)
	}

	//fmt.Printf("Here is the encrypted message: " + string(encryptedMessage) + "\n")
	decryptedMessage, err := symmetricDecrypt(encryptedMessage, keyBytes, nonce)

	if err != nil {
		log.Fatal("Error: %v", err)
	}

	fmt.Printf("Here is the decrypted message: " + string(decryptedMessage) + "\n")
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

func testHMAC() bool {
	var message string
	var hash []byte
	var key []byte

	message = "what the helly bron james"
	hash = createHMAC([]byte(message), key)

	//CHANGE MESSAGE TO VOID INTEGRITY
	//message = "what the helly bruh bruh bruh"
	return verifyHMAC([]byte(message), hash, key)
}

//////////////////     END     //////////////////

func genPubAndPrivKey() (*ecdh.PrivateKey, *ecdh.PublicKey) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal("Error: %v", err)
	}
	publicKey := privateKey.PublicKey()

	return privateKey, publicKey
}

func genSecret(publicKey *ecdh.PublicKey, privateKey *ecdh.PrivateKey) []byte {
	secret, err := privateKey.ECDH(publicKey)
	if err != nil {
		log.Fatal("Error: %v", err)
	}

	return secret
}

func ecdhTest() {
	bobPrivKey, bobPubKey := genPubAndPrivKey()
	alicePrivKey, alicePubKey := genPubAndPrivKey()

	bobSecret := genSecret(alicePubKey, bobPrivKey)
	aliceSecret := genSecret(bobPubKey, alicePrivKey)

	if !bytes.Equal(bobSecret, aliceSecret) {
		fmt.Printf("FAILED ECDH\n")
	} else {
		fmt.Printf("Successful ECDH!\n")
	}
}

// ////////////////    ECDSA    //////////////////
// Utilizing ECDSA to sign and verify delivery of an AES key
func createKeyPair() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Errorf("Something went wrong with generating a private key")
	}
	publicKey := &privateKey.PublicKey

	return privateKey, publicKey
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

func ecdsaTest() {
	privateKey, publicKey := createKeyPair()
	secretMessage := "What the helliantte"

	signature, err := sign(privateKey, []byte(secretMessage))
	if err != nil {
		fmt.Println("Signature failed!")
	}
	fmt.Println("Would you like to modify the secret message? If so, enter here, otherwise, press enter.")
	fmt.Print("Enter (empty for original): ")
	var newMessage string
	fmt.Scanln(&newMessage)
	if newMessage != "" {
		secretMessage = newMessage
	}
	if verify(publicKey, []byte(secretMessage), signature) == true {
		fmt.Println("Successful operation! Message is correct")
	} else {
		fmt.Println("The message was modified in transit")
	}
	fmt.Printf("Message: %s\n", secretMessage)

}

//////////////////     END     //////////////////

// func main() {
// 	testSymmetric()
// 	//ecdhTest()

	if testHMAC() {
		fmt.Println("What the helly bron james")
	} else {
		fmt.Println("What the helly burton")
	}

}
