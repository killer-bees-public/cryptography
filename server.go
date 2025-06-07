package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
)

func returnHandshake() {

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
		returnHandshake()
	} else {
		// Ignore connection
		return
	}

	for {

		message, err := bufio.NewReader(conn).ReadString('\n')
		// if string(message) == "Hello\n" {
		// 	fmt.Println("Initializing three way handshake")
		// }

		if err != nil {
			log.Fatal(err)

		}
		fmt.Printf("Message Received:", string(message))
		newMessage := strings.ToUpper((string(message)))
		conn.Write([]byte(newMessage + "\n"))
	}
}
