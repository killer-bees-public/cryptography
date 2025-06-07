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

	//HMAC the ciphertext, append to cipher
	hash := createHMAC(cipher, key)

	cipher = append(cipher, hash...)

	//Append nonce too
	cipher = append(cipher, nonce...)

	//cipher = data + HMAC + nonce

	//Send over socket
	//TODO

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

	if !verifyHMAC(data, hash, key) {
		//CLOSE CONNECTION
		fmt.Println("ERROR: Message has been altered during transmission!")
		fmt.Print("Closing connection...")
		return false
	}

	data, _ = symmetricDecrypt(data, key, nonce)

	//Read message into buffer
	*buffer = data
	return true
}