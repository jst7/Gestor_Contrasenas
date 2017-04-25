package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type usuarioBD struct {
	Name       string `json:"nombre"`
	Contraseña string `json:"contraseña"`
}
type usuario struct {
	Name       string   `json:"nombre"`
	Contraseña string   `json:"Contraseña"`
	Cuentas    []cuenta `json:"cuentas"`
}

type cuenta struct {
	Usuario    string `json:"usuario"`
	Contraseña string `json:"contraseña"`
	Servicio   string `json:"servicio"`
	//Clave string `json:"clave"`
	//ID    string `json:"id"`
}

type cookie struct {
	oreo   string    `json:"galleta"`
	expira time.Time `json:"expira"`
}

type peticion struct {
	Tipo    string   `json:"tipo"`
	Cookie  string   `json:"cookie"`
	Usuario usuario  `json:"usuario"`
	cuentas []cuenta `json:"cuentas"`
}

var galleta cookie

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

	var linea = "incorrecto"
	msg, _ := r.ReadString('\n')

	println("Mensaje recibido:")
	println(msg)

	var pet = jSONtoPeticion([]byte(msg))

	switch pet.Tipo {
	case "crearUsuario":
		if creacionUsuarioPorPeticion(pet) {
			linea = "----------------\nUsuario Creado\n----------------"
		} else {
			linea = "----------------\nUsuario ya Existente\n----------------"

		}
	case "sesion":
		fmt.Println("ENTRO")
		if recuperarSesion(pet) {
			//linea = "----------------\nSesión Iniciada\n----------------"
			var usuarioComprobar usuario

			usuarioComprobar.Name = pet.Usuario.Name
			usuarioComprobar.Contraseña = pet.Usuario.Contraseña
			usuarioComprobar.Cuentas = pet.Usuario.Cuentas
			pet := peticion{"sesIniciada", galleta.oreo, usuarioComprobar, nil}
			var peti = peticionToJSON(pet)
			conn.Write(peti)
		} else {
			linea = "----------------\nUsuario Incorrecto\n----------------"
		}
	case "cuentas":
		fmt.Println("Cuentas")
		//cuentas := JSONtoCuentas()
		//pet := peticion{"cuentas", galleta.oreo, cuentas}
		//var peti = peticionToJSON(pet)

		//conn.Write(peti)

	default:
		linea = "incorrecto"
	}
	println(linea)

	//conn.Write([]byte(linea))
	//n, _err := conn.Write([]byte(linea + "\n"))

}

/*func comprobarTipoPeticion(data Peticion) string {
	var devolucion = "otro"
	if data.Tipo == "crearUsuario" {
		devolucion = "creacion"
	}
	return devolucion
}*/

//crea la cookie para el usuario
func setCookie(usuario string) {
	galleta = cookie{oreo: usuario, expira: time.Now().Add(5000 * time.Second)}
	println(time.Now().String())

}

//devuelve la cookie con el nombre de usuario insertado
func getCookie() cookie {
	return galleta
}

//compara si la hora actual es anterior que la del expire de la cookie pasada por parametro
//si devuelve true es porque la sesion puede seguir activa, si devuelve false no
func statusCookie() bool {
	estado := false
	if time.Now().Before(galleta.expira) {
		estado = true
	}
	return estado

}

//añadido las cookies en recuperar sesion
func recuperarSesion(pet peticion) bool {

	var usuarioComprobar usuarioBD

	usuarioComprobar.Name = pet.Usuario.Name
	usuarioComprobar.Contraseña = pet.Usuario.Contraseña

	if iniciarSesion(usuarioComprobar) {
		return true
	}

	return false
}

func iniciarSesion(usuario usuarioBD) bool {
	var listaUSR = jSONtoUsuariosBD(leerArchivo("usuarios.json"))

	var entra = false
	for _, obj := range listaUSR {
		err := bcrypt.CompareHashAndPassword([]byte(obj.Name), []byte(usuario.Name))
		if err == nil {
			if strings.EqualFold(usuario.Contraseña, obj.Contraseña) {
				setCookie(obj.Name)
				entra = true
			}
		}
	}
	return entra
}

func creacionUsuarioPorPeticion(pet peticion) bool {
	var correcto = false
	var usuarios = jSONtoUsuariosBD(leerArchivo("usuarios.json"))
	var usuarioNuevo usuarioBD
	usuarioNuevo.Name = pet.Usuario.Name
	usuarioNuevo.Contraseña = pet.Usuario.Contraseña

	if !comprobarExistenciaUSR(usuarios, usuarioNuevo) {

		var nombre string
		password := []byte(pet.Usuario.Name)
		// Hashing the password with the default cost of 10
		hashedPassword, _ := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)

		for strings.Contains(string(hashedPassword), "/") { //Lo realizamos para que no genere con / ya que a la hora de directorios da problemas
			hashedPassword, _ = bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		}
		//fmt.Println(string(hashedPassword))
		nombre = string(hashedPassword)

		deleteFile("usuarios.json")
		createFile("usuarios.json")
		usuarioNuevo.Name = nombre
		var nuevalista = append(usuarios, usuarioNuevo)
		if escribirArchivoClientes("usuarios.json", string(usuariosBDToJSON(nuevalista))) {
			createFile(nombre + ".json")
			if pet.Usuario.Cuentas != nil {
				if escribirArchivoClientes(nombre+".json", string(cuentasToJSON(pet.Usuario.Cuentas))) {
					correcto = true
				} else {
					correcto = false
				}
			} else {
				if escribirArchivoClientes(nombre+".json", "[]") {
					correcto = true
				} else {
					correcto = false
				}
			}
		}
		setCookie(nombre)
	}

	return correcto
}
func comprobarExistenciaUSR(listaUSR []usuarioBD, usuario usuarioBD) bool {
	var existe = false
	for _, obj := range listaUSR {
		err := bcrypt.CompareHashAndPassword([]byte(obj.Name), []byte(usuario.Name))
		if err == nil {
			fmt.Println("EXISTE EL USUARIO SOLICITADO")
			existe = true
		}
	}
	return existe
}

func deleteFile(file string) {
	var err = os.Remove(file)
	if err != nil {
		panic(err)
	}
}

func leerArchivo(readfile string) []byte {

	dat, err := ioutil.ReadFile(readfile)
	if err != nil {
		panic(err)
	}
	return dat
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

func jSONtoPeticion(pet []byte) peticion { //desjoson

	var peticionDescifrado peticion
	json.Unmarshal(pet, &peticionDescifrado)

	return peticionDescifrado
}

func cuentasToJSON(cuent []cuenta) []byte { //Crear el json

	resultado, _ := json.Marshal(cuent)
	fmt.Printf("%s\n", resultado)
	return resultado
}

func usuariosBDToJSON(usrs []usuarioBD) []byte { //Crear el json

	resultado, _ := json.Marshal(usrs)
	fmt.Printf("%s\n", resultado)
	return resultado
}

func jSONtoUsuariosBD(usuariosDataFile []byte) []usuarioBD { //desjoson

	var usuariosDescifrado []usuarioBD
	json.Unmarshal(usuariosDataFile, &usuariosDescifrado)

	return usuariosDescifrado
}

func JSONtoCuentas() []cuenta {
	var listadeCuentas []cuenta
	json.Unmarshal([]byte(galleta.oreo), listadeCuentas)

	return listadeCuentas

}

func peticionToJSON(pet peticion) []byte {
	resultado, _ := json.Marshal(pet)
	fmt.Printf("%s\n", resultado)
	return resultado
}
