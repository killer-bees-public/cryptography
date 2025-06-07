package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
)

// Handshake is very simplified from normal TLS, sending first message
func initiateHandshake(conn net.Conn) {
	conn.Write([]byte("Hello\n"))

}

func main() {
	conn, err := net.Dial("tcp", "localhost:8000")
	if err != nil {
		log.Fatal(err)
	}

	// Client initializes contact with server
	initiateHandshake(conn)

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
