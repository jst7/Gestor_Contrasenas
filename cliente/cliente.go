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
)

/////////////////////////////////////
/////////	Estructuras		////////
///////////////////////////////////

type usuario struct {
	Name       string   `json:"nombre"`
	Contraseña string   `json:"contraseña"`
	Cuentas    []cuenta `json:"cuentas"` //Para almacenar mas de una cuenta
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
}
type respuesta struct {
	Estado     string `json:"estado"`
	Cookie     string `json:"cookie"`     //o token segun lo que implemente fran
	TipoCuerpo string `json:"tipocuerpo"` //tipo de dato del cuerpo
	Cuerpo     []byte `json:"respuesta"`
}

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

					} else if dentro == 2 { //Eliminar una cuenta concreta

					} else if dentro == 3 { //Modificar una cuenta

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

	//Conexión al servidor con la configuracion del tls
	conn, _ := tls.Dial("tcp", "localhost:443", conf)

	defer conn.Close()

	//Mensaje a enviar
	n, _ := conn.Write(enviar)
	conn.CloseWrite()
	//Respuesta del servidor
	//println("respuesta:")
	buf := make([]byte, 200)
	n, _ = conn.Read(buf)

	//println(string(buf[:n]))

	//var pet = jSONtoPeticion(buf[:n])
	var res = jSONtoRespuesta(buf[:n])
	println(string(res.Cuerpo[:]))
	//println(pet.Cookie)

	return string(buf[:n])
}
func menuComunicacion() int {
	println("1. Listar cuentas")
	println("2. Eliminar cuenta")
	println("3. Modificar cuenta")
	println("4. Cerrar Sesión")

	var op int
	fmt.Scanf("%d\n", &op)

	return op
}

/////////////////////////////////////////////
///////// TRABAJO CON USURIO	////////////
///////////////////////////////////////////
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

	UsuarioModificado := usuario{user.Name, user.Contraseña, contes}

	return UsuarioModificado
}
func crearUsuario() {
	//Datos de usuario
	var nombre string
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

	//Añadir primera cuenta
	println("¿Deseas añadir una cuenta?")
	fmt.Scanf("%s\n", &crear)

	//key del usuario
	var key []byte
	key = obtenerkeyUsuario(contraseñaUsuario)

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

	user := usuario{nombre, encriptar([]byte(contraseñaUsuario), key), contes}
	pet := peticion{"crearUsuario", "null", user, nil}
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

	user := usuario{nombre, contraseña, nil}
	pet := peticion{"sesion", "null", user, nil}
	var peti = peticionToJSON(pet)
	if comunicacion(peti) == "sesIniciada" { //"----------------\nSesión Iniciada\n----------------" {
		return true
	}

	return false
}
func jSONtoRespuesta(resp []byte) respuesta { //desjoson

	var respuestaDescifrado respuesta
	json.Unmarshal(resp, &respuestaDescifrado)

	return respuestaDescifrado
}

/////////////////////////////////////////////
///////// TRABAJO CON JSON	////////////////
///////////////////////////////////////////

func usuarioToJSON(user usuario) []byte { //Crear el json

	resultado, _ := json.Marshal(user)
	fmt.Printf("%s\n", resultado)
	return resultado
}

func peticionToJSON(pet peticion) []byte {
	resultado, _ := json.Marshal(pet)
	fmt.Printf("%s\n", resultado)
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
