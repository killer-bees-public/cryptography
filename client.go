package main

import (
	"bufio"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

const downloadedFile = "output.txt"

// Handshake is very simplified from normal TLS, sending first message, returns AES key in byte format
func initiateHandshake(conn net.Conn) []byte {
	clientPrivateKey, clientPublicKey := genPubAndPrivKey()

	conn.Write([]byte("Hello\n"))
	// Wait for a bit for a response
	time.Sleep(30000)
	reader := bufio.NewReader(conn)

	// Getting public Key for DH
	publicKeyRawBytes := readSectionOfPacket(reader)
	serverPublicKey, _ := ecdh.P256().NewPublicKey(publicKeyRawBytes)

	// Shared Secret AES Key
	sharedSecret := genSecret(serverPublicKey, clientPrivateKey)

	// Getting signature
	signatureFromServer := readSectionOfPacket(reader)

	// Reading parameters of ecDSA to generate object that can verify signature
	bigXBytes := readSectionOfPacket(reader)
	bigYBytes := readSectionOfPacket(reader)
	// Assume P256 for curve

	bigX := new(big.Int)
	bigY := new(big.Int)
	bigX.SetBytes(bigXBytes)
	bigY.SetBytes(bigYBytes)

	ecdsaPubKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     bigX,
		Y:     bigY,
	}

	if verify(&ecdsaPubKey, publicKeyRawBytes, signatureFromServer) == true {
		fmt.Println("Server successfully passed ecDSA. Continuing handshake")
		var DHReturnPacket []byte
		DHReturnPacket = addToPacket(DHReturnPacket, clientPublicKey.Bytes())
		n, err := conn.Write(DHReturnPacket)
		if n == 0 || err != nil {
			log.Fatal(err)
		}

		fmt.Println("Shared Secret:", sharedSecret)
		return sharedSecret
	} else {
		fmt.Println("Server Failed ecDSA. Terminating handshake...")
		conn.Close()
		return nil
	}

}

func readFile(conn net.Conn, key []byte) bool {
	reader := bufio.NewReader(conn)
	var cipherText []byte
	var err error
	var by byte
	for err == nil {
		by, err = reader.ReadByte()
		cipherText = append(cipherText, by)
	}
	cipherText = cipherText[:len(cipherText)-1]
	//fmt.Println(string(cipherText))

	var fileBytes []byte
	fileBytes, success := recv(cipherText, key)
	//fmt.Println("Decrypted message:", string(fileBytes))

	fd, error := os.Create("client/" + downloadedFile)
	fd.Write(fileBytes)
	if error != nil {
		log.Fatalf(error.Error())
	}
	return success
}

func main() {
	conn, err := net.Dial("tcp", "localhost:8000")
	if err != nil {
		log.Fatal(err)
	}

	// Client initializes contact with server
	sharedSecret := initiateHandshake(conn)
	if sharedSecret == nil {
		return
	}

	time.Sleep(30000)
	readFile(conn, sharedSecret)

	conn.Close()
	return
}
