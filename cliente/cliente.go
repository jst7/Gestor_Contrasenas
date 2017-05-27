package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

/////////////////////////////////////
/////////	Estructuras		////////
///////////////////////////////////

type usuario struct {
	Name    string   `json:"nombre"`
	Correo  string   `json:"correo"`
	Cuentas []cuenta `json:"cuentas"` //Para almacenar mas de una cuenta
}

type cuenta struct {
	Usuario    string `json:"usuario"`
	Contraseña string `json:"contraseña"`
	Servicio   string `json:"servicio"`
}
type peticion struct {
	Tipo    string   `json:"tipo"`
	Cookie  string   `json:"cookie"`
	Usuario usuario  `json:"usuario"`
	Cuentas []cuenta `json:"cuentas"`
	Clave   string   `json:"clave"`
}
type respuesta struct {
	Estado     string `json:"estado"`
	Cookie     string `json:"cookie"`     //o token segun lo que implemente fran
	TipoCuerpo string `json:"tipocuerpo"` //tipo de dato del cuerpo
	Cuerpo     []byte `json:"respuesta"`
}

type cookieIniciado struct {
	Valor string `json:"valor"`
	Hora  int    `json:"hora"`
}

var sesionUsuario cookieIniciado
var UsuarioConectado usuario
var keyuser []byte

/**
Todos las "_" se pueden sustituir por "err" y añadir el codigo:
	if err != nil {
		log.Println(err)
		return
	}
**/
/////////////////////////////////////
/////////	Metodos			////////
///////////////////////////////////
func main() {
	var op int

	//key := []byte("example key 1234")
	op = 0
	var dentro int
	for i := 1; op != 3; i++ {
		dentro = 0
		op = menu()
		if op == 1 { //Crear cuenta
			crearUsuario()
		} else if op == 2 { //Iniciar Sesión
			if pedirclave() {
				for j := 0; dentro != 4; j++ {
					dentro = menuComunicacion()

					if dentro == 1 { //Listar cuentas guardadas
						listarCuentas()
					} else if dentro == 2 { //Eliminar una cuenta concreta
						borrarCuentaServicio()
					} else if dentro == 3 { //Modificar una cuenta

					} else if dentro == 5 { //Modificar una cuenta
						fmt.Println(sesionUsuario)
					} else { //Cerrar sesión

					}

				}
			}
		} else { //Salir del programa

		}
	}
}

func menu() int {
	println("1. Crear cuenta nueva")
	println("2. Recuperar datos")
	println("3. Salir")

	var op int
	fmt.Scanf("%d\n", &op)

	return op
}

/////////////////////////////////////////////
///////// TRABAJO CON Comunicacion	////////
///////////////////////////////////////////
func comunicacion(enviar []byte) string {
	flag.Parse()
	log.SetFlags(log.Lshortfile)

	conf := &tls.Config{ //Para aceptar certificados no firmados
		InsecureSkipVerify: true,
	}

	conn, _ := tls.Dial("tcp", "localhost:443", conf)
	defer conn.Close()
	n, _ := conn.Write(enviar)
	conn.CloseWrite()
	buf := make([]byte, 50000)
	n, _ = conn.Read(buf)
	//println(string(buf[:n]))
	return string(buf[:n])
}
func menuComunicacion() int {
	println("1. Listar cuentas")
	println("2. Eliminar cuenta")
	println("3. Modificar cuenta")
	println("4. Cerrar Sesión")
	println("5. Mostrar cookie")

	var op int
	fmt.Scanf("%d\n", &op)

	return op
}

/////////////////////////////////////////////
///////// TRABAJO CON USUARIO	////////////
///////////////////////////////////////////
func añadirCuentaAUsuario(user usuario) usuario { //revisar problema al quitar la contraseña del usuario

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

	UsuarioModificado := usuario{user.Name, user.Correo, contes}

	return UsuarioModificado
}
func crearUsuario() {

	//Datos de usuario
	var nombre string
	var correo string
	var contraseñaUsuario string
	var contes []cuenta

	//Datos de cuenta
	var usuarioNombre string
	var contraseñaCuenta string
	var servicio string

	//Booleano de añadir cuenta
	var crear string

	//Datos de Usuario
	println("Nombre del usuario")
	fmt.Scanf("%s\n", &nombre)

	println("Contraseña")
	fmt.Scanf("%s\n", &contraseñaUsuario)

	println("Correo del usuario")
	fmt.Scanf("%s\n", &correo)

	//Añadir primera cuenta
	println("¿Deseas añadir una cuenta?")
	fmt.Scanf("%s\n", &crear)

	//key del usuario
	var key []byte
	key = obtenerkeyUsuario(contraseñaUsuario)
	keyuser = key
	if crear == "si" {
		for crear != "no" {
			println("Usuario:")
			fmt.Scanf("%s\n", &usuarioNombre)
			println("Contraseña:")
			fmt.Scanf("%s\n", &contraseñaCuenta)
			println("Servicio:")
			fmt.Scanf("%s\n", &servicio)
			n := cuenta{encriptar([]byte(usuarioNombre), key), encriptar([]byte(contraseñaCuenta), key), encriptar([]byte(servicio), key)}
			contes = append(contes, n)
			println("¿Deseas añadir otra cuenta?")
			fmt.Scanf("%s\n", &crear)
		}
	}

	//
	//HASH USUARIO CONTRASEÑA
	//
	password := []byte(nombre + contraseñaUsuario)
	// Hashing the password with the default cost of 10
	hashedPassword, _ := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)

	for strings.Contains(string(hashedPassword), "/") { //Lo realizamos para que no genere con / ya que a la hora de directorios da problemas
		hashedPassword, _ = bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	}
	//fmt.Println(string(hashedPassword))
	nombre = string(hashedPassword)
	//
	//HASH USUARIO CONTRASEÑA
	//

	user := usuario{nombre, correo, contes}
	pet := peticion{"crearUsuario", "null", user, nil, ""}
	var peti = peticionToJSON(pet)
	comunicacion(peti)
}
func obtenerkeyUsuario(contraseña string) []byte {
	var salida string
	salida = contraseña
	for {
		if len(salida) == 16 {
			return []byte(salida)
		} else {
			salida = salida + "0"
		}
	}
}

func pedirclave() bool {
	var nombre string
	var contraseña string

	println("Introduce tu usuario:")
	fmt.Scanf("%s\n", &nombre)

	println("Introduce tu contraseña:")
	fmt.Scanf("%s\n", &contraseña)

	//key del usuario
	//var key []byte
	keyuser = obtenerkeyUsuario(contraseña)

	user := usuario{nombre + contraseña, "", nil}
	pet := peticion{"sesion", "null", user, nil, ""}
	var peti = peticionToJSON(pet)
	var comunicacion = comunicacion(peti)
	var respuesta = jSONtoRespuesta([]byte(comunicacion))

	if respuesta.Estado == "Correcto" { //"----------------\nSesión Iniciada\n----------------" {

		t := time.Now()
		var stringHora = string(t.Format("20060102150405"))
		enteroHora, _ := strconv.Atoi(stringHora)
		//SESIÓN
		sesionUsuario.Hora = enteroHora
		sesionUsuario.Valor = respuesta.Cookie

		if claveCorreo(nombre + contraseña) {
			fmt.Println("--------------------------------------------------")
			UsuarioConectado = user
			println(UsuarioConectado.Name)
			return true
			return true
		} else {
			return false
		}

	}
	fmt.Println("Ha ocurrido un error: " + string(respuesta.Cuerpo))
	return false
}

/////////////////////////////////////////////
///////// TRABAJO CON CUENTAS	////////////
///////////////////////////////////////////
func listarCuentas() {

	var listCuentasdisponbls []cuenta
	UsuarioConectado.Cuentas = nil

	pet := peticion{"getcuentas", "null", UsuarioConectado, nil, ""}

	var peti = peticionToJSON(pet)
	var comunicacionDel = comunicacion(peti)
	var respuesta = jSONtoRespuesta([]byte(comunicacionDel))
	//println(string(respuesta.Cuerpo))
	cuentasRespuesta := jSONtoCuentas(respuesta.Cuerpo)
	for _, obj := range cuentasRespuesta {
		listCuentasdisponbls = append(listCuentasdisponbls, cuenta{desencriptar(obj.Usuario, keyuser), desencriptar(obj.Contraseña, keyuser), desencriptar(obj.Servicio, keyuser)})
	}
	listaCuentas(listCuentasdisponbls)
}
func listaCuentas(cuents []cuenta) {

	println("-----Seleccione la cuenta a borrar----")
	println("--Usuario--------------Servicio--------------Contraseña")

	for _, obj := range cuents {
		println(obj.Usuario + "			" + obj.Servicio + "			" + obj.Contraseña)
	}

}
func modificarCuentas() {

	var cuentaname string
	var servicio string
	var cuentaNNombre string
	var servicioNServi string
	var nuevoPassword string

	var nuevaListaCuentas []cuenta
	var listCuentasdisponbls []cuenta

	UsuarioConectado.Cuentas = nil
	pet := peticion{"actualizarCuenta", "null", UsuarioConectado, nil, ""}

	var peti = peticionToJSON(pet)
	var comunicacionDel = comunicacion(peti)
	var respuesta = jSONtoRespuesta([]byte(comunicacionDel))
	//println(string(respuesta.Cuerpo))
	cuentasRespuesta := jSONtoCuentas(respuesta.Cuerpo)
	for _, obj := range cuentasRespuesta {
		listCuentasdisponbls = append(listCuentasdisponbls, cuenta{desencriptar(obj.Usuario, keyuser), desencriptar(obj.Contraseña, keyuser), desencriptar(obj.Servicio, keyuser)})
	}
	listaCuentas(listCuentasdisponbls)
	fmt.Print("Introduce cuenta a modificar: ")
	fmt.Scanf("%s\n", &cuentaname)
	fmt.Print("Introduce servicio a modificar: ")
	fmt.Scanf("%s\n", &servicio)

	fmt.Print("Introduce nuevo nombre para la cuenta " + cuentaname + ": ")
	fmt.Scanf("%s\n", &cuentaNNombre)
	fmt.Print("Introduce nuevo servicio para la cuenta " + cuentaname + " del servicio " + servicio + ": ")
	fmt.Scanf("%s\n", &servicioNServi)
	fmt.Print("Introduce nueva contraseña para la cuenta " + cuentaname + ": ")
	fmt.Scanf("%s\n", &nuevoPassword)

	var cuentaModificada = cuenta{encriptar([]byte(cuentaNNombre), keyuser), encriptar([]byte(nuevoPassword), keyuser), encriptar([]byte(servicioNServi), keyuser)}
	for _, obj := range listCuentasdisponbls {
		if obj.Usuario != cuentaname || obj.Servicio != servicio {
			obj = cuenta{encriptar([]byte(obj.Usuario), keyuser), obj.Contraseña, encriptar([]byte(obj.Servicio), keyuser)}
			nuevaListaCuentas = append(nuevaListaCuentas, obj)
		}
	}

	nuevaListaCuentas = append(nuevaListaCuentas, cuentaModificada)
	UsuarioConectado.Cuentas = nuevaListaCuentas
	peticionActu := peticion{"actualizarCuenta", "null", UsuarioConectado, nuevaListaCuentas, ""}

	var petiActu = peticionToJSON(peticionActu)
	var comunicacionActu = comunicacion(petiActu)
	var respuestaActu = jSONtoRespuesta([]byte(comunicacionActu))

	if string(respuestaActu.Estado) == "Correcto" {
		println("Borrado realizado correctamente")
	} else if string(respuestaActu.Estado) == "Incorrecto" {
		println("Borrado no realizado")
	}
}
func borrarCuentaServicio() {

	var cuentaname string
	var servicio string

	var nuevaListaCuentas []cuenta
	var listCuentasdisponbls []cuenta

	UsuarioConectado.Cuentas = nil
	pet := peticion{"delcuentas", "null", UsuarioConectado, nil, ""}

	var peti = peticionToJSON(pet)
	var comunicacionDel = comunicacion(peti)
	var respuesta = jSONtoRespuesta([]byte(comunicacionDel))
	//println(string(respuesta.Cuerpo))
	cuentasRespuesta := jSONtoCuentas(respuesta.Cuerpo)
	for _, obj := range cuentasRespuesta {
		listCuentasdisponbls = append(listCuentasdisponbls, cuenta{desencriptar(obj.Usuario, keyuser), obj.Contraseña, desencriptar(obj.Servicio, keyuser)})
	}
	menuBorrado(listCuentasdisponbls)
	fmt.Print("Introduce cuenta a borrar: ")
	fmt.Scanf("%s\n", &cuentaname)
	fmt.Print("Introduce servicio a borrar: ")
	fmt.Scanf("%s\n", &servicio)

	for _, obj := range listCuentasdisponbls {
		if obj.Usuario != cuentaname || obj.Servicio != servicio {
			obj = cuenta{encriptar([]byte(obj.Usuario), keyuser), obj.Contraseña, encriptar([]byte(obj.Servicio), keyuser)}
			nuevaListaCuentas = append(nuevaListaCuentas, obj)
		}
	}
	UsuarioConectado.Cuentas = nuevaListaCuentas
	peticionActu := peticion{"delcuentas", "null", UsuarioConectado, nuevaListaCuentas, ""}

	var petiActu = peticionToJSON(peticionActu)
	var comunicacionActu = comunicacion(petiActu)
	var respuestaActu = jSONtoRespuesta([]byte(comunicacionActu))

	if string(respuestaActu.Estado) == "Correcto" {
		println("Borrado realizado correctamente")
	} else if string(respuestaActu.Estado) == "Incorrecto" {
		println("Borrado no realizado")
	}

}

func menuBorrado(cuents []cuenta) {

	println("-----Seleccione la cuenta a borrar----")
	println("--Usuario---------------Servicio--")

	for _, obj := range cuents {
		println(obj.Usuario + "			" + obj.Servicio)
	}

}

/////////////////////////////////////////////
///////// TRABAJO CON JSON	////////////////
///////////////////////////////////////////
func jSONtoRespuesta(resp []byte) respuesta { //desjoson

	var respuestaDescifrado respuesta
	json.Unmarshal(resp, &respuestaDescifrado)

	return respuestaDescifrado
}
func usuarioToJSON(user usuario) []byte { //Crear el json

	resultado, _ := json.Marshal(user)
	//fmt.Printf("%s\n", resultado)
	return resultado
}
func peticionToJSON(pet peticion) []byte {
	resultado, _ := json.Marshal(pet)
	//fmt.Printf("%s\n", resultado)
	return resultado
}

func jSONtoUsuario(user []byte) usuario { //desjoson

	var usuarioDescifrado usuario
	json.Unmarshal(user, &usuarioDescifrado)

	return usuarioDescifrado

}
func jSONtoPeticion(pet []byte) peticion { //desjoson

	var peticionDescifrado peticion
	json.Unmarshal(pet, &peticionDescifrado)

	return peticionDescifrado
}
func jSONtoCuentas(datos []byte) []cuenta {
	var listadeCuentas []cuenta
	json.Unmarshal(datos, &listadeCuentas)

	return listadeCuentas

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

/////////////////////////////////////////////
///////// TRABAJO CON Correo		////////
///////////////////////////////////////////
func claveCorreo(nombre string) bool {
	var clave string
	fmt.Print("Introduce la clave enviada a tu correo:")
	fmt.Scanf("%s\n", &clave)

	user := usuario{nombre, "", nil}
	pet := peticion{"autcorreo", sesionUsuario.Valor, user, nil, clave}
	var peti = peticionToJSON(pet)
	var comunicacion = comunicacion(peti)
	var respuesta = jSONtoRespuesta([]byte(comunicacion))

	if respuesta.Estado == "Correcto" {
		return true
	} else {
		return false
	}

}
