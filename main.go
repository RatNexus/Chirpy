package main

import (
	"fmt"
	"net/http"
	"os"
)

func exitWithError(err error) {
	fmt.Println(err)
	os.Exit(1)
}

func main() {
	serveMux := http.NewServeMux()
	server := &http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	fmt.Println("Start server.")
	err := server.ListenAndServe()
	if err != nil {
		fmt.Println("Server exited with an error.")
		exitWithError(err)
	}
	fmt.Println("Server exited with no errors.")
}
