package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	mrand "math/rand"
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
	Clave  string `json:"clave"`
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
	Tipo    string   `json:"tipo"`
	Cookie  string   `json:"cookie"`
	Usuario usuario  `json:"usuario"`
	Clave   string   `json:"clave"`
	Cuentas []cuenta `json:"cuenta"`
}

type respuesta struct {
	Estado     string `json:"estado"`
	Cookie     string `json:"cookie"`
	TipoCuerpo string `json:"tipocuerpo"`
	Cuerpo     []byte `json:"respuesta"`
}

type correoValor struct {
	Correo string `json:"correo"`
	clave  string `json:"clave"`
}

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

var listaCookies []cookie
var listaCorreoClave []correoValor

var tamCookie = 50
var expira = 180
var keyEncripArch = []byte("claveServidor123")

/////////////////////////////////////
/////////	Funciones		////////
///////////////////////////////////

func main() {
	log.SetFlags(log.Lshortfile)

	println("1. Comprobar log")
	println("2. Arrancar servidor")

	var op int
	fmt.Scanf("%d\n", &op)

	if op == 1 {
		fmt.Println(string(leerArchivoLog("log.txt")))
	} else if op == 2 {
		fmt.Printf("------------------------------------\nARRANCADO EL SERVIDOR\n------------------------------------\n")

		cer, _ := tls.LoadX509KeyPair("server.crt", "server.key")

		config := &tls.Config{Certificates: []tls.Certificate{cer}}
		ln, _ := tls.Listen("tcp", ":443", config)

		defer ln.Close()

		for {
			conn, _ := ln.Accept()

			go handleConnection(conn)
		}

	}
}

/////////////////////////////////////////////
///////// TRABAJO CON CONEXION	////////////
///////////////////////////////////////////
func handleConnection(conn net.Conn) {
	escribirLog("Petición")
	vaciarCookie()
	defer conn.Close()
	r := bufio.NewReader(conn)

	var resp []byte
	msg, _ := r.ReadString('\n')

	var pet = jSONtoPeticion([]byte(msg))

	switch pet.Tipo {
	case "crearUsuario":
		escribirLog("crear Usuario")
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
		escribirLog("inicio Sesion")
		if recuperarSesion(pet) {
			escribirLog("Sesión iniciada")
			//"----------------\nSesión Iniciada\n----------------"
			res := respuesta{"Correcto", getCookieUsuarios(pet.Usuario.Name).Oreo, "string", []byte("log completo")} //falta meter la cookie
			email(recuperarCorreoUsuario(pet.Usuario.Name), recuperarClave(recuperarCorreoUsuario(pet.Usuario.Name)))
			resp = respuestaToJSON(res)

		} else {
			//"----------------\nUsuario Incorrecto\n----------------"
			res := respuesta{"Incorrecto", getCookieUsuarios("").Oreo, "string", []byte("No se ha podido iniciar sesión")}
			resp = respuestaToJSON(res)
		}

	case "autcorreo":
		escribirLog("auto correo")
		if comprobarCookieValida(pet) {
			if recuperarSesionCorreo(recuperarCorreo(pet.Usuario), pet.Clave) {
				res := respuesta{"Correcto", getCookieUsuarios(pet.Usuario.Name).Oreo, "string", []byte("log completo con correo")} //falta meter la cookie
				resp = respuestaToJSON(res)
			} else {
				res := respuesta{"Incorrecto", getCookieUsuarios("").Oreo, "string", []byte("No se ha podido iniciar sesión")}
				resp = respuestaToJSON(res)
			}
		} else {
			fmt.Print("sesion caudcada")
		}
	case "getcuentas":
		escribirLog("Obtener cuentas")
		if comprobarCookieValida(pet) {

			res := respuesta{"Correcto", getCookieUsuarios(obtenerUsuarioCookie(pet)).Oreo, "string", devolvercuentasUsuario(pet)}
			resp = respuestaToJSON(res)
		} else {
			fmt.Print("sesion caudcada")
		}

	case "delcuentas":
		escribirLog("Borrar cuentas")
		if comprobarCookieValida(pet) {
			if pet.Usuario.Cuentas == nil {
				var stin = devolvercuentasUsuario(pet)
				res := respuesta{"Correcto", getCookieUsuarios(obtenerUsuarioCookie(pet)).Oreo, "string", stin}
				resp = respuestaToJSON(res)

			} else {

				var resul = actualizarcuentas(pet)
				if resul {
					res := respuesta{"Correcto", getCookieUsuarios("").Oreo, "string", []byte("Cuenta Borrada")}
					resp = respuestaToJSON(res)
				} else {
					res := respuesta{"Incorrecto", getCookieUsuarios("").Oreo, "string", []byte("Cuenta no borrada")}
					resp = respuestaToJSON(res)
				}
			}
		} else {
			fmt.Print("sesion caudcada")

		}
	case "actualizarCuenta":
		escribirLog("Actualizar Cuenta")
		if comprobarCookieValida(pet) {
			if pet.Usuario.Cuentas == nil {
				var stin = devolvercuentasUsuario(pet)
				res := respuesta{"Correcto", getCookieUsuarios(obtenerUsuarioCookie(pet)).Oreo, "string", stin}
				resp = respuestaToJSON(res)
			} else {
				var resul = actualizarcuentas(pet)
				if resul {
					res := respuesta{"Correcto", getCookieUsuarios("").Oreo, "string", []byte("Cuenta Actualizada")}
					resp = respuestaToJSON(res)
				} else {
					res := respuesta{"Incorrecto", getCookieUsuarios("").Oreo, "string", []byte("Cuenta no Actualizada")}
					resp = respuestaToJSON(res)
				}
			}
		} else {
			fmt.Print("sesion caudcada")

		}
	default:
		escribirLog("Peticion incorrecta")
		res := respuesta{"Incorrecto", getCookieUsuarios("").Oreo, "string", []byte("Ha ocurrido un error")}
		resp = respuestaToJSON(res)
	}
	conn.Write(resp)

}

/////////////////////////////////////////////
///////////	 TRABAJO CON COOKIES	////////
///////////////////////////////////////////
//crea la cookie para el usuario
func setCookie(n int) string {
	token, err := GenerateRandomString(n)
	if err != nil {

	}
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

func vaciarCookie() {
	t := time.Now()
	var stringHora = string(t.Format("20060102150405"))
	enteroHora, _ := strconv.Atoi(stringHora)

	var cookieLimpiar []cookie

	for i := range listaCookies {
		if horaCookie(enteroHora, listaCookies[i].Expira) {
			cookieLimpiar = append(cookieLimpiar, listaCookies[i])
		}
	}
	listaCookies = cookieLimpiar
}

func comprobarCookieValida(pet peticion) bool {

	t := time.Now()
	var stringHora = string(t.Format("20060102150405"))
	enteroHora, _ := strconv.Atoi(stringHora)

	for i := range listaCookies {
		if listaCookies[i].Oreo == pet.Cookie {
			if horaCookie(enteroHora, listaCookies[i].Expira) {
				listaCookies[i].Expira = enteroHora
				return true
			}
		}
	}
	return false
}

func obtenerUsuarioCookie(pet peticion) string {
	for i := range listaCookies {
		if listaCookies[i].Oreo == pet.Cookie {
			return listaCookies[i].Usuario
		}
	}

	return ""
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
//////// TRABAJO CON CUENTAS	////////////
///////////////////////////////////////////
func devolvercuentasUsuario(pet peticion) []byte {
	var listaUSR = jSONtoUsuariosBD(leerArchivo("usuarios.json"))

	for _, obj := range listaUSR {
		err := bcrypt.CompareHashAndPassword([]byte(obj.Name), []byte(pet.Usuario.Name))

		if err == nil {

			return leerArchivo(obj.Name + ".json")
		}
	}
	return []byte("error al ler archivo")
}

func actualizarcuentas(pet peticion) bool {
	var resultado = false
	var listaUSR = jSONtoUsuariosBD(leerArchivo("usuarios.json"))

	for _, obj := range listaUSR {
		err := bcrypt.CompareHashAndPassword([]byte(obj.Name), []byte(pet.Usuario.Name))
		if err == nil {

			deleteFile(obj.Name + ".json")
			createFile(obj.Name + ".json")
			escribirArchivoClientes(obj.Name+".json", string(cuentasToJSON(pet.Usuario.Cuentas)))
			resultado = true

		}
	}

	return resultado
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

func iniciarSesion(usuario usuarioBD) bool {
	var listaUSR = jSONtoUsuariosBD(leerArchivo("usuarios.json"))

	var entra = false
	for _, obj := range listaUSR {
		err := bcrypt.CompareHashAndPassword([]byte(obj.Name), []byte(usuario.Name))
		if err == nil {
			//hacemos la cookie
			t := time.Now()
			var stringHora = string(t.Format("20060102150405"))
			enteroHora, _ := strconv.Atoi(stringHora)

			n := cookie{obj.Name, setCookie(tamCookie), enteroHora}
			listaCookies = append(listaCookies, n)

			entra = true
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

	if !comprobarExistenciaUSR(usuarios, usuarioNuevo) {
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
			existe = true
		}
	}
	return existe
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

	var leer = true
	dat, err := ioutil.ReadFile(readfile)
	if err != nil {
		if readfile == "usuarios.json" {
			createFile("usuarios.json")
			leer = false
		} else if readfile == "log.txt" {
			createFile("log.txt")
			leer = false
		} else {
			panic(err)
		}

	}
	if leer && string(dat) != "" {
		dat = []byte(desencriptar(string(dat), keyEncripArch))
	}

	return dat
}

func leerArchivoLog(readfile string) string {

	var leer = true
	dat, err := ioutil.ReadFile(readfile)
	if err != nil {
		if readfile == "log.txt" {
			createFile("log.txt")
			leer = false
		} else {
			panic(err)
		}
	}
	var log = string(dat)
	var lineas = strings.Split(log, "\n")
	var res string

	for i := range lineas {
		if leer && lineas[i] != "" {
			res = res + "\n" + desencriptar(lineas[i], keyEncripArch)
		}
	}

	return res
}

func createFile(filename string) {
	var _, err = os.Stat(filename)

	if os.IsNotExist(err) {
		var file, err = os.Create(filename)
		if err != nil {
			os.Exit(0)
		}
		defer file.Close()
	}
}
func escribirArchivoClientes(file string, data string) bool {

	data = encriptar([]byte(data), keyEncripArch)

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

func jSONtoCuentas(datos []byte) []cuenta {
	var listadeCuentas []cuenta
	json.Unmarshal(datos, &listadeCuentas)

	return listadeCuentas

}

func peticionToJSON(pet peticion) []byte {
	resultado, _ := json.Marshal(pet)
	return resultado
}

func respuestaToJSON(res respuesta) []byte {
	resultado, _ := json.Marshal(res)
	return resultado
}

/////////////////////////////////////////////
///////////	 TRABAJO CON ENCRIPTACION	////
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

/////////////////////////////////////////////
///////////	 TRABAJO CON CORREO			////
///////////////////////////////////////////

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

	log.Println("Email enviado correctamete, doble autentificación")
}

func recuperarCorreoUsuario(usuario string) string {
	var listaUSR = jSONtoUsuariosBD(leerArchivo("usuarios.json"))

	for _, obj := range listaUSR {
		//print(obj.Name + " " + usuario.Name)
		err := bcrypt.CompareHashAndPassword([]byte(obj.Name), []byte(usuario))
		if err == nil {

			key := mrand.Intn(9999)
			valor := correoValor{obj.Correo, strconv.Itoa(key)}

			for i := range listaCorreoClave {
				if listaCorreoClave[i].Correo == obj.Correo {
					listaCorreoClave[i].clave = strconv.Itoa(key)
					return obj.Correo
				}
			}

			listaCorreoClave = append(listaCorreoClave, valor)
			return obj.Correo
		}
	}
	return "sdspoleo@gmail.com"
}

func recuperarClave(correo string) string {

	for _, obj := range listaCorreoClave {

		if obj.Correo == correo {
			return obj.clave
		}
	}
	return "ERROR ️☹"

}

func recuperarCorreo(user usuario) string {
	var listaUSR = jSONtoUsuariosBD(leerArchivo("usuarios.json"))

	for _, obj := range listaUSR {
		err := bcrypt.CompareHashAndPassword([]byte(obj.Name), []byte(user.Name))
		if err == nil {
			return obj.Correo
		}
	}
	return ""
}

func recuperarSesionCorreo(correo string, clave string) bool {

	for _, obj := range listaCorreoClave {
		if obj.Correo == correo && obj.clave == clave {
			return true
		}
	}

	return false
}

/////////////////////////////////////////////
///////////	 TRABAJO CON LOG	////////////
///////////////////////////////////////////
func escribirLog(data string) bool {
	leerArchivo("log.txt")
	var log = false
	t := time.Now()
	var stringHora = string(t.Format("20060102150405"))
	var linea = stringHora + ": " + data
	log = escribirArchivoClientes("log.txt", linea)

	return log
}

/////////////////////////////////////////////
///////// TRABAJO CON Encriptacion	////////
///////////////////////////////////////////
func encriptar(datosPlanos []byte, key []byte) string {
	plaintext := datosPlanos

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return base64.URLEncoding.EncodeToString(ciphertext)
}

func desencriptar(datosEncriptados string, key []byte) string {

	ciphertext, _ := base64.URLEncoding.DecodeString(datosEncriptados)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}
