package main

import (
	//"bufio"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	//"log"
	//"net"
	//"os"
)

const hashSize = 32
const nonceSize = 16

func send(data []byte, key []byte, conn net.Conn) []byte {
	//Encrypt message
	nonce := make([]byte, 16)
	rand.Read(nonce)
	cipher, err := symmetricEncrypt(data, key[:16], nonce)
	if err != nil {
		log.Fatalf(err.Error())

	}

	//HMAC the ciphertext, append to cipher
	hash := createHMAC(cipher, key[16:])

	cipher = append(cipher, hash...)

	//Append nonce too
	cipher = append(cipher, nonce...)

	//cipher = data + HMAC + nonce

	//Send over socket
	conn.Write(cipher)
	fmt.Println("Sending", len(cipher), "Encrypted Bytes to client")
	return cipher
}

func recv(cipher []byte, key []byte) ([]byte, bool) {
	//Calculate indices to slice bytes
	fmt.Println("Received", len(cipher), "Encrypted Bytes from server")
	endOfData := len(cipher) - (hashSize + nonceSize)
	endOfHMAC := len(cipher) - nonceSize

	//Split up bytes
	data := cipher[0:endOfData]
	hash := cipher[endOfData:endOfHMAC]
	nonce := cipher[endOfHMAC:]
	//fmt.Println(len(cipher))

	if !verifyHMAC(data, hash, key[16:]) {
		//CLOSE CONNECTION
		fmt.Println("ERROR: Message has been altered during transmission!")
		fmt.Println("Closing connection...")
		return nil, false
	}

	data, err := symmetricDecrypt(data, key[:16], nonce)
	if err != nil {
		log.Fatalf(err.Error())
	}
	//Read message into buffer

	return data, true
}
