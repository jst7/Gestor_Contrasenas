package main

import (
	"fmt"
	"log"
	"net/http"
)

func saludoInicio(w http.ResponseWriter, r *http.Request) {

	fmt.Fprintf(w, "<h1> Servidor arrancado 9797 </h1>")
}

func main() {
	http.HandleFunc("/", saludoInicio)       // define la ruta
	err := http.ListenAndServe(":9797", nil) //  establece el puerto de escucha
	if err != nil {
		log.Fatal("Error: ", err)
	}
}
