package main

import (
	"crypto/tls"
	"fmt"
	"log"
)

/**
* Todos las "_" se pueden sustituir por "err" y descomentar el codigo justo de debajo para conocer el error.
*
**/
func main() {
	log.SetFlags(log.Lshortfile)

	conf := &tls.Config{ //Para aceptar certificados no firmados
		InsecureSkipVerify: true,
	}

	//Conexión al servidor con la configuracion del tls
	conn, _ := tls.Dial("tcp", "localhost:443", conf)
	/*if err != nil {
		log.Println(err)
		return
	}*/
	defer conn.Close()

	//Mensaje a enviar
	println("Mensaje a enviar:")
	var linea string
	fmt.Scanf("%s", &linea)

	n, _ := conn.Write([]byte(linea + "\n"))
	/*if err != nil {
		log.Println(n, err)
		return
	}*/

	//Respuesta del servidor
	println("respuesta:")
	buf := make([]byte, 100)
	n, _ = conn.Read(buf)
	/*if err != nil {
		log.Println(n, err)
		return
	}*/
	println(string(buf[:n]))
}
