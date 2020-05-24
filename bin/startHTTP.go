package main

import (
	"log"
	"net/http"
	"os"

	"github.com/lkzcover/goproxy/v2/lib"
)

func main() {

	port := os.Getenv("PORT")

	if port == "" {
		port = "9000"
	}

	log.Printf("Info: start listen port: %s", port)

	key := os.Getenv("KEY")

	httpServer := lib.HTTPServer{Key: key}

	_ = http.ListenAndServe(":"+port, &httpServer)

}
