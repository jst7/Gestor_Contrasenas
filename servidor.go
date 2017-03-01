package main

import (
	"fmt"
	"log"
	"net/http"
)

func saludoInicio(w http.ResponseWriter, r *http.Request) {

	fmt.Fprintf(w, "<h1> Servidor arrancado 9797 </h1>")
}

func main() { //https://localhost/
	http.HandleFunc("/", saludoInicio)                                     // define la ruta
	err := http.ListenAndServeTLS(":443", "server.crt", "server.key", nil) //  establece el puerto de escucha
	if err != nil {
		log.Fatal("Error: ", err)
	}
}
