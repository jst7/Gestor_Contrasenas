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

	switch pet.Tipo {
	case "crearUsuario":
		if CreacionUsuarioPorPeticion(pet) {
			linea = "----------------\nUsuario Creado\n----------------"
		} else {
			linea = "----------------\nUsuario ya Existente\n----------------"

		}
	case "sesion":
		fmt.Println("ENTRO")
		if recuperarSesion(pet) {
			linea = "----------------\nSesión Iniciada\n----------------"
		} else {
			linea = "----------------\nUsuario Incorrecto\n----------------"
		}
	default:
		linea = "incorrecto"
	}

	conn.Write([]byte(linea))
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

func recuperarSesion(peticion Peticion) bool {

	var usuarioComprobar usuarioBD

	usuarioComprobar.Name = peticion.Usuario.Name
	usuarioComprobar.Contraseña = peticion.Usuario.Contraseña

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
				entra = true
			}
		}
	}
	return entra
}

func CreacionUsuarioPorPeticion(peticion Peticion) bool {
	var correcto = false
	var usuarios = jSONtoUsuariosBD(leerArchivo("usuarios.json"))
	var usuarioNuevo usuarioBD
	usuarioNuevo.Name = peticion.Usuario.Name
	usuarioNuevo.Contraseña = peticion.Usuario.Contraseña

	if !comprobarExistenciaUSR(usuarios, usuarioNuevo) {

		var nombre string
		password := []byte(peticion.Usuario.Name)
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
		if escribirArchivoClientes("usuarios.json", string(UsuariosBDToJSON(nuevalista))) {
			createFile(nombre + ".json")
			if peticion.Usuario.Cuentas != nil {
				if escribirArchivoClientes(nombre+".json", string(CuentasToJSON(peticion.Usuario.Cuentas))) {
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

func UsuariosBDToJSON(usrs []usuarioBD) []byte { //Crear el json

	resultado, _ := json.Marshal(usrs)
	fmt.Printf("%s\n", resultado)
	return resultado
}

func jSONtoUsuariosBD(usuariosDataFile []byte) []usuarioBD { //desjoson

	var usuariosDescifrado []usuarioBD
	json.Unmarshal(usuariosDataFile, &usuariosDescifrado)

	return usuariosDescifrado
}
