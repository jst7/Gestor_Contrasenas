package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type usuario struct {
	Name    string   `json:"nombre"`
	Datos   string   `json:"datos"`
	Cuentas []cuenta `json:"cuentas"`
}

type cuenta struct {
	Usuario    string `json:"usuario"`
	Contraseña string `json:"contraseña"`
	Servicio   string `json:"servicio"`
	//Clave string `json:"clave"`
	//ID    string `json:"id"`
}

type cookie struct {
	user   string
	expira time.Time
}

type Peticion struct {
	Tipo    string  `json:"tipo"`
	Usuario usuario `json:"usuario"`
}

var galletas []cookie

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

	var pet = jSONtoPeticion([]byte(msg))

	switch comprobarTipoPeticion(pet) {
	case "creacion":
		if CreacionUsuarioPorPeticion(pet) {
			linea = "correcto"
		}
	default:
		linea = "incorrecto"
	}

	conn.Write([]byte(linea))
	//n, _err := conn.Write([]byte(linea + "\n"))

}

func comprobarTipoPeticion(data Peticion) string {
	var devolucion = "otro"
	if data.Tipo == "crearUsuario" {
		devolucion = "creacion"
	}
	return devolucion
}

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

func CreacionUsuarioPorPeticion(peticion Peticion) bool {
	var correcto = false

	if escribirArchivoClientes("usuarios.json", "{ \"nombre:\""+peticion.Usuario.Name+"\"datos:\""+peticion.Usuario.Datos+"}") {
		createFile(peticion.Usuario.Name + ".json")
		if escribirArchivoClientes(peticion.Usuario.Name+".json", string(CuentasToJSON(peticion.Usuario.Cuentas))) {
			correcto = true
		} else {
			correcto = false
		}
	}

	return correcto
}
func createFile(filename string) {
	// detect if file exists
	var _, err = os.Stat(filename)

	// create file if not exists
	if os.IsNotExist(err) {
		var file, err = os.Create(filename)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(0)
		}
		defer file.Close()
	}
}
func escribirArchivoClientes(file string, data string) bool {

	var escrito = false
	if file != "" {
		f, err := os.OpenFile(file, os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal(err)
		} else {
			_, error := f.WriteString(data + "\n")
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

func jSONtoPeticion(peticion []byte) Peticion { //desjoson

	var peticionDescifrado Peticion
	json.Unmarshal(peticion, &peticionDescifrado)

	return peticionDescifrado
}

func CuentasToJSON(cuent []cuenta) []byte { //Crear el json

	resultado, _ := json.Marshal(cuent)
	fmt.Printf("%s\n", resultado)
	return resultado
}
