package main

import (
	"log"
	"net/http"
	"os"

	"github.com/lkzcover/goproxy/lib"
)

func main() {

	port := os.Getenv("PORT")

	if port == "" {
		port = "9000"
	}

	log.Printf("Info: start listen port: %s", port)

	var httpServer lib.HTTPServer

	_ = http.ListenAndServe(":"+port, &httpServer)

}
