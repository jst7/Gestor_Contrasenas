package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
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
			if pedirclave() {
				menuComunicacion()
			}
		} else {

		}
	}
}

func menuComunicacion() {

}

func pedirclave() bool {
	var archivo string
	println("Introduce tu archivo:")
	fmt.Scanf("%s\n", &archivo)

	dat, err := ioutil.ReadFile(archivo)
	if err != nil {
		//log.Println(err)
		println("No se ha podido leer el archivo: " + archivo)
		return false
	}
	return sesion(string(dat))
}

func sesion(datos string) bool {
	println(datos)
	comunicacion(datos)
	return true
}

func menu() int {
	println("1. Crear cuenta nueva")
	println("2. Recuperar datos")
	println("3. Salir")

	var op int
	fmt.Scanf("%d\n", &op)

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
	fmt.Scanf("%s\n", &nombre)
	println("Datos adicionales")
	fmt.Scanf("%s\n", &datos)

	//Añadir primera cuenta
	println("¿Deseas añadir una cuenta?")
	fmt.Scanf("%s\n", &crear)

	if crear == "si" {
		for crear != "no" {
			println("Usuario:")
			fmt.Scanf("%s\n", &usuarioNombre)
			println("Contraseña:")
			fmt.Scanf("%s\n", &contraseña)
			println("Servicio:")
			fmt.Scanf("%s\n", &servicio)
			n := cuenta{usuarioNombre, contraseña, servicio}
			contes = append(contes, n)
			println("¿Deseas añadir otra cuenta?")
			fmt.Scanf("%s\n", &crear)
		}
	}

	user := usuario{nombre, datos, contes}
	usuarioToJSON(user)
}

func comunicacion(enviar string) {
	log.SetFlags(log.Lshortfile)

	conf := &tls.Config{ //Para aceptar certificados no firmados
		InsecureSkipVerify: true,
	}

	//Conexión al servidor con la configuracion del tls
	conn, _ := tls.Dial("tcp", "localhost:443", conf)

	defer conn.Close()

	//Mensaje a enviar
	n, _ := conn.Write([]byte(enviar))

	//Respuesta del servidor
	println("respuesta:")
	buf := make([]byte, 100)
	n, _ = conn.Read(buf)

	println(string(buf[:n]))
}

func usuarioToJSON(user usuario) []byte { //Crear el json

	resultado, _ := json.Marshal(user)
	//fmt.Printf("%s\n", resultado)

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
	fmt.Scanf("%s\n", &usuarioNombre)
	println("Contraseña:")
	fmt.Scanf("%s\n", &contraseña)
	println("Servicio:")
	fmt.Scanf("%s\n", &servicio)
	n := cuenta{usuarioNombre, contraseña, servicio}
	contes = append(user.Cuentas, n)

	UsuarioModificado := usuario{user.Name, user.Datos, contes}

	return UsuarioModificado
}

//metodo que muestra los datos formateados de un usuario
func leerUsuario(user usuario) {

	println(user.Name)

	for i := 0; i < len(user.Cuentas); i++ {
		println("---------")
		println("Servicio: " + user.Cuentas[i].Servicio)
		println("Usuario: " + user.Cuentas[i].Usuario)
		println("Contraseña: " + user.Cuentas[i].Contraseña)
	}
	println()

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
