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

	// conn.Write([]byte("bruh\n"))
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("Text to send: ")
		text, _ := reader.ReadString('\n')

		fmt.Fprintf(conn, text+"\n")
		message, _ := bufio.NewReader(conn).ReadString('\n')
		fmt.Printf("Message from server: " + message)
	}
}
