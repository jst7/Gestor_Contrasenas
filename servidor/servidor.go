package main

import (
	"bufio"
	"crypto/tls"
	"log"
	"net"
	"os"
	"strings"
	"time"
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
	//var oreo cookie

	var linea = "incorrecto"
	msg, _ := r.ReadString('\n')

	println("Mensaje recibido:")
	println(msg)
	/*setCookie(msg)
	oreo := getCookie(msg)
	println("usuario: " + oreo.user + " - Tiempo: " + oreo.expira.String())
	if statusCookie(msg) {
		println("Entra")
	} else {
		println("No Entra")
	}*/
	println("mensaje a responder(enviar):")

	if escribirArchivoClientes("prueba.json", msg) {
		linea = "correcto"
	}

	conn.Write([]byte(linea))
	//n, _err := conn.Write([]byte(linea + "\n"))

}

type usuario struct {
	Cuentas []cuenta `json:"cuentas"`
}

type cuenta struct {
	Clave string `json:"clave"`
	ID    string `json:"id"`
}

type cookie struct {
	user   string
	expira time.Time
}

var galletas []cookie

//crea la cookie para el usuario
func setCookie(usuario string) {
	galleta := cookie{user: usuario, expira: time.Now().Add(50 * time.Second)}
	println(time.Now().String())
	galletas = append(galletas, galleta)

}

//devuelve la cookie con el nombre de usuario insertado
func getCookie(usuario string) cookie {
	encontrado := false
	var oreo cookie
	for i := 0; i < len(galletas) && encontrado == false; i++ {

		if strings.Compare(galletas[i].user, usuario) == 0 {
			oreo = cookie{user: galletas[i].user, expira: galletas[i].expira}
			encontrado = true
		}
	}

	return oreo

}

//compara si la hora actual es anterior que la del expire de la cookie pasada por parametro
func statusCookie(usuario string) bool {
	encontrado := false
	var oreo cookie
	for i := 0; i < len(galletas) && encontrado == false; i++ {

		if strings.Compare(galletas[i].user, usuario) == 0 {
			oreo = cookie{user: galletas[i].user, expira: galletas[i].expira}
			encontrado = true
		}
	}

	if encontrado == true {
		if time.Now().Before(oreo.expira) {
			return true
		} else {
			return false
		}

	}

	return encontrado

}

func escribirArchivoClientes(file string, data string) bool {

	var escrito = false
	if file != "" {
		f, err := os.OpenFile(file, os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal(err)
		} else {
			_, error := f.WriteString(data)
			if error != nil {
				log.Fatal(error)
			}

			escrito = true

			f.Sync()
			f.Close()
		}
	}

	return escrito
}
