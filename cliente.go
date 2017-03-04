package main

import (
	"crypto/tls"
	"fmt"
	"log"
)

/**
Todos las "_" se pueden sustituir por "err" y añadir el codigo:
	if err != nil {
		log.Println(err)
		return
	}
**/
func main() {
	comunicacion()
	/*
		for i := 1; i < 3; i++ {
			i = menu()

			if i == 1 {

			} else if i == 2 {
				comunicacion()
			} else {

			}
		}*/
}

func menu() int {
	println("1. Crear cuenta nueva")
	println("2. Recuperar datos")
	println("3. Salir")

	var op int
	fmt.Scan(&op)

	return op
}

func comunicacion() {
	log.SetFlags(log.Lshortfile)

	conf := &tls.Config{ //Para aceptar certificados no firmados
		InsecureSkipVerify: true,
	}

	//Conexión al servidor con la configuracion del tls
	conn, _ := tls.Dial("tcp", "localhost:443", conf)

	defer conn.Close()

	//Mensaje a enviar
	println("Mensaje a enviar:")
	var linea string
	fmt.Scanf("%s", &linea)
	n, _ := conn.Write([]byte(linea + "\n"))

	//Respuesta del servidor
	println("respuesta:")
	buf := make([]byte, 100)
	n, _ = conn.Read(buf)

	println(string(buf[:n]))
}

//Estructura JSON
func createJson() string {

	return ""
}

type Usuario struct {
	Name     string
	servidor string
	cuentas  []Cuenta //Para almacenar mas de una cuenta
}

type Cuenta struct {
	usuario    string
	contraseña string
	servicio   string
}
