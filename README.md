# Gestor_Contrasenas

Hemos creado los certificados

usando:
**Key considerations for algorithm "RSA" ≥ 2048-bit**
`
openssl genrsa -out server.key 2048
`

** Key considerations for algorithm "ECDSA" ≥ secp384r1
List ECDSA the supported curves (openssl ecparam -list_curves)**
`
openssl ecparam -genkey -name secp384r1 -out server.key
`
**Generation of self-signed(x509) public key (PEM-encodings .pem|.crt) based on the private (.key)**

``openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650``


```GO
package main

import (
    "net/http"
    "log"
)

func HelloServer(w http.ResponseWriter, req *http.Request) {
    w.Header().Set("Content-Type", "text/plain")
    w.Write([]byte("This is an example server.\n"))
}

func main() {
    http.HandleFunc("/hello", HelloServer)
    err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil)
    if err != nil {
        log.Fatal("ListenAndServe: ", err)
    }
}
```