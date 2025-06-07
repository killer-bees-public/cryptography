package main

import (
	//"bufio"
	"crypto/rand"
	"fmt"
	//"log"
	//"net"
	//"os"
)

const hashSize = 32
const nonceSize = 16

func send(data []byte, key []byte) ([]byte) {
	//Encrypt message
	nonce := make([]byte, len(key))
	rand.Read(nonce)
	cipher, _ := symmetricEncrypt(data, key, nonce)

	fmt.Printf("LEN OF CIPHER: %d\n", len(cipher))

	//HMAC the ciphertext, append to cipher
	hash := createHMAC(cipher, key)
	fmt.Printf("LEN OF HASH: %d\n", len(hash))
	fmt.Printf("LEN OF NONCE: %d\n", len(nonce))


	cipher = append(cipher, hash...)

	//Append nonce too
	cipher = append(cipher, nonce...)

	//cipher = data + HMAC + nonce

	//Send over socket
	//TODO

	fmt.Printf("LEN OF EVERYTHING: %d\n", len(cipher))

	fmt.Printf("SEND HASH: %s\n", hash)
	fmt.Printf("SEND NONCE: %s\n", nonce)

	return cipher
}

func recv(cipher []byte, buffer *[]byte, key []byte) (bool) {
	//Calculate indices to slice bytes
	endOfData := len(cipher) - (hashSize + nonceSize)
	endOfHMAC := len(cipher) - nonceSize

	//Split up bytes
	data := cipher[0 : endOfData]
	hash := cipher[endOfData : endOfHMAC]
	nonce := cipher[endOfHMAC : ]

	fmt.Printf("LEN OF HASH: %d\n", len(hash))
	fmt.Printf("LEN OF NONCE: %d\n", len(nonce))
	fmt.Printf("LEN OF DATA: %d\n", len(data))
	fmt.Printf("LEN OF EVERYTHING: %d\n", len(cipher))

	fmt.Printf("RECV HASH: %s\n", hash)
	fmt.Printf("RECV NONCE: %s\n", nonce)


	data, _ = symmetricDecrypt(data, key, nonce)

	if !verifyHMAC(data, hash, key) {
		//CLOSE CONNECTION
		fmt.Println("bad hmac!!")
		//return false
	}

	//Read message into buffer
	*buffer = data
	return true
}