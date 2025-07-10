package main

import (
	"fmt"
	"net/http"
	"os"
)

func exitWithError(err error) {
	fmt.Println("Server exited with an error.")
	fmt.Println(err)
	os.Exit(1)
}

func main() {
	serveMux := http.NewServeMux()
	serveMux.Handle("/", http.FileServer(http.Dir("./static/")))

	server := &http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	fmt.Println("Start server on http://localhost:8080/")
	err := server.ListenAndServe()
	if err != nil {
		exitWithError(err)
	}
	fmt.Println("Server exited with no errors.")
}
