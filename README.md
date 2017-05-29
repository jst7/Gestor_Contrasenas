# Gestor de Contraseñas
### Indice
#### Otras alternativas

#### Nuesstra Práctica

- Certificados
- Comunicación		
- Optativo
	- Servidor de Correo
	- Conocimiento 0
		
- Metodología de trabajo
- Puesta en marcha

	
## Otras alternativas
## Nuestra Práctica
### Certificados

Hemos creado los certificados

Usando:
**Key considerations for algorithm "RSA" ≥ 2048-bit**
`
openssl genrsa -out server.key 2048
`
`
openssl ecparam -genkey -name secp384r1 -out server.key
`
``openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650``

Para la comunicación algo similar en base a esto en el cliente y servidor:

```GO
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

//conexion entre el cliente y el servidor
func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		msg, _ := r.ReadString('\n')

		println("Mensaje recibido:")
		println(msg)
		println("mensaje a responder(enviar):")
		var linea string
		fmt.Scanf("%s\n", &linea)

		conn.Write([]byte(linea + "\n"))
		//n, _err := conn.Write([]byte(linea + "\n"))

	}

}

```
### Comunicación
Para la comunicación hemos realizado un tunel TLS con cabeceras entre cliente y servidor.
Para ello hemos creado una estructura con estos campos:

**Servidor:**

```GO

type peticion struct {
	Tipo    string   `json:"tipo"`
	Cookie  string   `json:"cookie"`
	Usuario usuario  `json:"usuario"`
	Clave   string   `json:"clave"`
	Cuentas []cuenta `json:"cuenta"`
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
```

Lo importante seria la cabecera tipo que sería la que redigiría las peticiones del cliente. Por otro lado, tenemos la cookie para la sesion, usuario que es un tipo de usuario y cuentas.

**Cliente:**



### Puesta en marcha
