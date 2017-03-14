package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
)

/**
Todos las "_" se pueden sustituir por "err" y añadir el codigo:
	if err != nil {
		log.Println(err)
		return
	}
**/
func main() {
	log.SetFlags(log.Lshortfile)

	cer, _ := tls.LoadX509KeyPair("server.crt", "server.key")

	config := &tls.Config{Certificates: []tls.Certificate{cer}}
	ln, _ := tls.Listen("tcp", ":443", config)

	defer ln.Close()

	for {
		conn, _ := ln.Accept()

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, _ := r.ReadString('\n')

		println("Mensaje recibido:")
		println(msg)
		exribirArchivoClientes("prueba.txt", msg)
		println("mensaje a responder(enviar):")
		var linea string
		fmt.Scanf("%s\n", &linea)

		conn.Write([]byte(linea + "\n"))
		//n, _err := conn.Write([]byte(linea + "\n"))

	}

}

type usuario struct {
	Cuentas []cuenta `json:"cuentas"`
}

type cuenta struct {
	Clave string `json:"clave"`
	ID    string `json:"id"`
}

func exribirArchivoClientes(file string, data string) bool {
	var escrito = false
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			log.Fatal(err)
		} else {
			_, error := f.WriteString(data)
			if error != nil {
				log.Fatal(err)
			}

			escrito = true

			f.Sync()

		}
	}

	return escrito
}
