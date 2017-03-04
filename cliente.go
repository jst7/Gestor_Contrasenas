package main

import (
	"crypto/tls"
	"encoding/json"
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
	//comunicacion()
	createJSON()
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
func createJSON() string {

	m := cuenta{"Jorge", "1234", "Facebook"}
	n := cuenta{"Jorge", "1234", "Facebook"}

	var contes []cuenta

	contes = append(contes, m)
	contes = append(contes, n)

	user := usuario{"jorge segovia", "el mejor del mundo", contes}

	resultado, _ := json.Marshal(user)
	fmt.Printf("%s\n", resultado)

	return string(resultado)
}

type usuario struct {
	Name    string   `json:"nombre"`
	Datos   string   `json:"datos"`
	Cuentas []cuenta `json:"cuentas"` //Para almacenar mas de una cuenta
}

type cuenta struct {
	Usuario    string `json:"usuario"`
	Contraseña string `json:"contraseña"`
	Servicio   string `json:"servicio"`
}
