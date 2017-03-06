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

	var op int
	op = 0
	for i := 1; op != 3; i++ {
		op = menu()
		if op == 1 {
			crearUsuario()
		} else if op == 2 {
			comunicacion()
		} else {

		}
	}
}

func menu() int {
	println("1. Crear cuenta nueva")
	println("2. Recuperar datos")
	println("3. Salir")

	var op int
	fmt.Scan(&op)

	return op
}

func crearUsuario() {
	//Datos de usuario
	var nombre string
	var datos string
	var contes []cuenta

	//Datos de cuenta
	var usuarioNombre string
	var contraseña string
	var servicio string

	//Booleano de añadir cuenta
	var crear string

	//Datos de Usuario
	println("Nombre del usuario")
	fmt.Scan(&nombre)
	println("Datos adicionales")
	fmt.Scan(&datos)

	//Añadir primera cuenta
	println("¿Deseas añadir una cuenta?")
	fmt.Scan(&crear)

	if crear == "si" {
		for crear != "no" {
			println("Usuario:")
			fmt.Scan(&usuarioNombre)
			println("Contraseña:")
			fmt.Scan(&contraseña)
			println("Servicio:")
			fmt.Scan(&servicio)
			n := cuenta{usuarioNombre, contraseña, servicio}
			contes = append(contes, n)
			println("¿Deseas añadir otra cuenta?")
			fmt.Scan(&crear)
		}
	}

	user := usuario{nombre, datos, contes}
	usuarioToJSON(user)
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

func usuarioToJSON(user usuario) []byte { //Crear el json

	resultado, _ := json.Marshal(user)
	fmt.Printf("%s\n", resultado)

	return resultado
}

func jSONtoUsuario(user []byte) usuario { //Crear el json

	var usuarioDescifrado usuario
	json.Unmarshal(user, &usuarioDescifrado)

	return usuarioDescifrado
}

func añadirCuentaAUsuario(user usuario) usuario {

	//Datos de cuenta
	var usuarioNombre string
	var contraseña string
	var servicio string
	var contes []cuenta

	println("Usuario:")
	fmt.Scan(&usuarioNombre)
	println("Contraseña:")
	fmt.Scan(&contraseña)
	println("Servicio:")
	fmt.Scan(&servicio)
	n := cuenta{usuarioNombre, contraseña, servicio}
	contes = append(user.Cuentas, n)

	UsuarioModificado := usuario{user.Name, user.Datos, contes}

	return UsuarioModificado
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
