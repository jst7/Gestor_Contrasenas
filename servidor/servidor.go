package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

/////////////////////////////////////
/////////	Estructuras		////////
///////////////////////////////////

type usuarioBD struct {
	Name   string `json:"nombre"`
	Correo string `json:"correo"`
}
type usuario struct {
	Name    string   `json:"nombre"`
	Correo  string   `json:"correo"`
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
	Usuario string `json:"usuario"`
	Oreo    string `json:"galleta"`
	Expira  int    `json:"expira"`
}

type peticion struct {
	Tipo    string  `json:"tipo"`
	Cookie  string  `json:"cookie"`
	Usuario usuario `json:"usuario"`
}

type respuesta struct {
	Estado     string `json:"estado"`
	Cookie     string `json:"cookie"`     //o token segun lo que implemente fran
	TipoCuerpo string `json:"tipocuerpo"` //tipo de dato del cuerpo
	Cuerpo     []byte `json:"respuesta"`
}

var listaCookies []cookie

var tamCookie = 50
var expira = 180

/////////////////////////////////////
/////////	Funciones		////////
///////////////////////////////////

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

/////////////////////////////////////////////
///////// TRABAJO CON CONEXION	////////////
///////////////////////////////////////////
func handleConnection(conn net.Conn) {

	defer conn.Close()
	r := bufio.NewReader(conn)

	var resp []byte

	//var linea = "incorrecto"
	msg, _ := r.ReadString('\n')

	//println("Mensaje recibido:")
	//println(msg)

	var pet = jSONtoPeticion([]byte(msg))

	switch pet.Tipo {
	case "crearUsuario":
		if creacionUsuarioPorPeticion(pet) {
			// "----------------\nUsuario Creado\n----------------"

			res := respuesta{"Correcto", getCookieUsuarios("").Oreo, "string", []byte("Usuario creado correctamente")} //falta meter la cookie
			resp = respuestaToJSON(res)

		} else {
			// "----------------\nUsuario ya Existente\n----------------"
			res := respuesta{"Incorrecto", getCookieUsuarios("").Oreo, "string", []byte("Usuario no creado, ya existe un usuario")}
			resp = respuestaToJSON(res)
		}

	case "sesion":

		if recuperarSesion(pet) {
			//"----------------\nSesión Iniciada\n----------------"
			fmt.Println(listaCookies)
			res := respuesta{"Correcto", getCookieUsuarios(pet.Usuario.Name).Oreo, "string", []byte("log completo")} //falta meter la cookie
			email(recuperarCorreoUsuario(pet.Usuario.Name), "clave")
			resp = respuestaToJSON(res)

		} else {
			//"----------------\nUsuario Incorrecto\n----------------"
			res := respuesta{"Incorrecto", getCookieUsuarios("").Oreo, "string", []byte("No se ha podido iniciar sesión")}
			resp = respuestaToJSON(res)
		}

	case "autcorreo":

		if recuperarSesionCorreo(pet) {
			res := respuesta{"Correcto", getCookieUsuarios(pet.Usuario.Name).Oreo, "string", []byte("log completo con correo")} //falta meter la cookie
			resp = respuestaToJSON(res)
		} else {
			res := respuesta{"Incorrecto", getCookieUsuarios("").Oreo, "string", []byte("No se ha podido iniciar sesión")}
			resp = respuestaToJSON(res)
		}
	case "cuentas":

		if comprobarCookieValida(pet) {
			//fmt.Println("Cuentas")
			res := respuesta{"Correcto", getCookieUsuarios("").Oreo, "string", []byte("Cuentas son las siguientes")} //falta meter la cookie
			resp = respuestaToJSON(res)
		}

	default:

		//linea = "incorrecto"
		res := respuesta{"Incorrecto", getCookieUsuarios("").Oreo, "string", []byte("Ha ocurrido un error")} //falta meter la cookie
		resp = respuestaToJSON(res)
	}

	//println(linea)
	conn.Write(resp)

}

/////////////////////////////////////////////
///////////	 TRABAJO CON COOKIES	////////
///////////////////////////////////////////
//crea la cookie para el usuario
func setCookie(n int) string {
	token, err := GenerateRandomString(n)
	if err != nil {
		// Serve an appropriately vague error to the
		// user, but log the details internally.
	}
	//println(time.Now().String())
	return token
}

//devuelve la Cookie del usuario
func getCookieUsuarios(usuario string) cookie {

	var userHash string
	var usuarios = jSONtoUsuariosBD(leerArchivo("usuarios.json"))

	for _, obj := range usuarios {
		err := bcrypt.CompareHashAndPassword([]byte(obj.Name), []byte(usuario))
		if err == nil {
			userHash = obj.Name
		}
	}

	for _, obj := range listaCookies {
		if obj.Usuario == userHash {
			return obj
		}
	}

	var vacio cookie
	return vacio
}

func comprobarCookieValida(pet peticion) bool {
	//realizar para trabajar con cookies y establecer el usuario
	return true
}

//compara si la hora actual es anterior que la del expire de la cookie pasada por parametro
//si devuelve true es porque la sesion puede seguir activa, si devuelve false no
func horaCookie(peticion int, caduca int) bool {

	estado := false
	if (peticion - caduca) < expira {
		estado = true
	}

	return estado

}

/////////////////////////////////////////////
//////// TRABAJO CON USUARIOS	////////////
///////////////////////////////////////////

//añadido las cookies en recuperar sesion
func recuperarSesion(pet peticion) bool {

	var usuarioComprobar usuarioBD

	usuarioComprobar.Name = pet.Usuario.Name

	if iniciarSesion(usuarioComprobar) {

		return true
	}

	return false
}

func recuperarSesionCorreo(pet peticion) bool {

	return true
}

func iniciarSesion(usuario usuarioBD) bool {
	var listaUSR = jSONtoUsuariosBD(leerArchivo("usuarios.json"))

	var entra = false
	for _, obj := range listaUSR {
		//print(obj.Name + " " + usuario.Name)
		err := bcrypt.CompareHashAndPassword([]byte(obj.Name), []byte(usuario.Name))
		if err == nil {
			//hacemos la cookie
			t := time.Now()
			var stringHora = string(t.Format("20060102150405"))
			enteroHora, _ := strconv.Atoi(stringHora)

			n := cookie{obj.Name, setCookie(tamCookie), enteroHora}
			listaCookies = append(listaCookies, n)

			entra = true
			println("hola entro")
		}
	}
	return entra
}

func creacionUsuarioPorPeticion(pet peticion) bool {
	var correcto = false
	var usuarios = jSONtoUsuariosBD(leerArchivo("usuarios.json"))
	var usuarioNuevo usuarioBD
	usuarioNuevo.Name = pet.Usuario.Name
	usuarioNuevo.Correo = pet.Usuario.Correo
	//println("AQUI " + pet.Usuario.Name)

	if !comprobarExistenciaUSR(usuarios, usuarioNuevo) {
		//println("ENTRA")
		var nombre string

		nombre = pet.Usuario.Name

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
		setCookie(tamCookie)
	}

	return correcto
}
func comprobarExistenciaUSR(listaUSR []usuarioBD, usuario usuarioBD) bool {
	var existe = false
	for _, obj := range listaUSR {
		err := bcrypt.CompareHashAndPassword([]byte(obj.Name), []byte(usuario.Name))
		if err == nil {
			//fmt.Println("EXISTE EL USUARIO SOLICITADO")
			existe = true
		}
	}
	return existe
}
func devolvercuentasUsuario(pet peticion) []byte {
	return leerArchivo(pet.Usuario.Name)
}

/////////////////////////////////////////////
///////////	 TRABAJO CON ARCHIVOS	////////
///////////////////////////////////////////
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
			//fmt.Println(err.Error())
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

func escribirLog(data string) bool {
	var log = false
	log = escribirArchivoClientes("log.txt", data)

	return log
}

/////////////////////////////////////////////
///////////	 TRABAJO CON JSON	////////////
///////////////////////////////////////////
func jSONtoPeticion(pet []byte) peticion { //desjoson

	var peticionDescifrado peticion
	json.Unmarshal(pet, &peticionDescifrado)

	return peticionDescifrado
}

func cuentasToJSON(cuent []cuenta) []byte { //Crear el json

	resultado, _ := json.Marshal(cuent)
	//fmt.Printf("%s\n", resultado)
	return resultado
}

func usuariosBDToJSON(usrs []usuarioBD) []byte { //Crear el json

	resultado, _ := json.Marshal(usrs)
	//fmt.Printf("%s\n", resultado)
	return resultado
}

func jSONtoUsuariosBD(usuariosDataFile []byte) []usuarioBD { //desjoson

	var usuariosDescifrado []usuarioBD
	json.Unmarshal(usuariosDataFile, &usuariosDescifrado)

	return usuariosDescifrado
}

func jSONtoCuentas(galleta cookie) []cuenta {
	var listadeCuentas []cuenta
	json.Unmarshal([]byte(galleta.Oreo), listadeCuentas)

	return listadeCuentas

}

func peticionToJSON(pet peticion) []byte {
	resultado, _ := json.Marshal(pet)
	//fmt.Printf("%s\n", resultado)
	return resultado
}

func respuestaToJSON(res respuesta) []byte {
	resultado, _ := json.Marshal(res)
	//fmt.Printf("%s\n", resultado)
	return resultado
}

/////////////////////////////////////////////
///////////	 TRABAJO CON ECRIPTACION	////
///////////////////////////////////////////

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomString(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

//EMAIL de autenticación
type Mail struct {
	senderId string
	toIds    []string
	subject  string
	body     string
}

type SmtpServer struct {
	host string
	port string
}

func (s *SmtpServer) ServerName() string {
	return s.host + ":" + s.port
}

func (mail *Mail) BuildMessage() string {
	message := ""
	message += fmt.Sprintf("From: %s\r\n", mail.senderId)
	if len(mail.toIds) > 0 {
		message += fmt.Sprintf("To: %s\r\n", strings.Join(mail.toIds, ";"))
	}

	message += fmt.Sprintf("Subject: %s\r\n", mail.subject)
	message += "\r\n" + mail.body

	return message
}

func email(correo string, mensaje string) {

	mail := Mail{}
	mail.senderId = "sdspoleo@gmail.com"
	mail.toIds = []string{correo}
	mail.subject = "Autentificacion"
	mail.body = mensaje

	messageBody := mail.BuildMessage()

	smtpServer := SmtpServer{host: "smtp.gmail.com", port: "465"}

	log.Println(smtpServer.host)
	//build an auth
	auth := smtp.PlainAuth("", mail.senderId, "qwertyqwerty", smtpServer.host)

	// Gmail will reject connection if it's not secure
	// TLS config
	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         smtpServer.host,
	}

	conn, err := tls.Dial("tcp", smtpServer.ServerName(), tlsconfig)
	if err != nil {
		log.Panic(err)
	}

	client, err := smtp.NewClient(conn, smtpServer.host)
	if err != nil {
		log.Panic(err)
	}

	// step 1: Use Auth
	if err = client.Auth(auth); err != nil {
		log.Panic(err)
	}

	// step 2: add all from and to
	if err = client.Mail(mail.senderId); err != nil {
		log.Panic(err)
	}
	for _, k := range mail.toIds {
		if err = client.Rcpt(k); err != nil {
			log.Panic(err)
		}
	}

	// Data
	w, err := client.Data()
	if err != nil {
		log.Panic(err)
	}

	_, err = w.Write([]byte(messageBody))
	if err != nil {
		log.Panic(err)
	}

	err = w.Close()
	if err != nil {
		log.Panic(err)
	}

	client.Quit()

	log.Println("Mail sent successfully")
}

func recuperarCorreoUsuario(usuario string) string {
	return "jorge.segovia.tormo@gmail.com"
}
