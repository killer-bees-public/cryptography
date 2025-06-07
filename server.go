package main

import (
	"bufio"
	"crypto/ecdh"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

const fileToCopy = "recursiveBruh.txt"

// Returns handshake from
func returnHandshake(conn net.Conn) []byte {

	reader := bufio.NewReader(conn)

	serverPrivateKey, serverPublicKey := genPubAndPrivKey()

	// Need digital signature (ecdsa) to verify servers publicKey in Diffie Hellman
	ecDSAPriv, ecDSAPub := createKeyPair()
	signature, _ := sign(ecDSAPriv, serverPublicKey.Bytes())

	var sizeOfPacket uint16 = uint16(len(serverPublicKey.Bytes()) + len(signature) + 64 + 2)
	size := make([]byte, 2)
	binary.BigEndian.PutUint16(size, sizeOfPacket)
	var DSAPacket []byte
	DSAPacket = addToPacket(DSAPacket, serverPublicKey.Bytes())
	DSAPacket = addToPacket(DSAPacket, signature)
	DSAPacket = addToPacket(DSAPacket, ecDSAPub.X.Bytes())
	DSAPacket = addToPacket(DSAPacket, ecDSAPub.Y.Bytes())

	fmt.Println("Sending initial response with DH Public key, signature, and DSA Public Key")
	conn.Write(DSAPacket)

	time.Sleep(30000)
	// Next, we'll need to read the response that the client will send with its public key for DH
	clientPublicKeyRawBytes := readSectionOfPacket(reader)
	clientPublicKey, err := ecdh.P256().NewPublicKey(clientPublicKeyRawBytes)

	if err != nil {
		log.Fatal(err)
	}

	// Shared Secret AES Key
	sharedSecret := genSecret(clientPublicKey, serverPrivateKey)

	fmt.Println("Shared Secret:", sharedSecret)
	return sharedSecret
}

func sendSecretFile(conn net.Conn, key []byte) {
	bytes, _ := os.ReadFile("server/" + fileToCopy)
	send(bytes, key, conn)
	return
}
func main() {
	ln, err := net.Listen("tcp", ":8000")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Listening on port 8000")
	conn, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}

	message, err := bufio.NewReader(conn).ReadString('\n')
	if string(message) == "Hello\n" {
		fmt.Println("Initializing three way handshake")
		sharedSecret := returnHandshake(conn)
		time.Sleep(30000)
		sendSecretFile(conn, sharedSecret)
	} else {
		// Ignore connection
		return
	}

}
