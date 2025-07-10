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
	serveMux.Handle("/app/", http.StripPrefix("/app/", http.FileServer(http.Dir("./static/"))))

	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}

	serveMux.HandleFunc("/healthz", healthHandler)

	server := &http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	fmt.Println("Start server on http://localhost:8080/app")
	err := server.ListenAndServe()
	if err != nil {
		exitWithError(err)
	}
	fmt.Println("Server exited with no errors.")
}
