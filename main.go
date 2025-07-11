package main

import (
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
)

func exitWithError(err error) {
	fmt.Println("Server exited with an error.")
	fmt.Println(err)
	os.Exit(1)
}

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func main() {
	serveMux := http.NewServeMux()
	apiCfg := &apiConfig{}
	apiCfg.fileserverHits.Store(0)

	appHandler := http.StripPrefix("/app/", http.FileServer(http.Dir("./static/")))

	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(appHandler))

	healthHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}

	hitsHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(200)
		template := `<html>
	<body>
		<h1>Welcome, Chirpy Admin</h1>
		<p>Chirpy has been visited %d times!</p>
	</body>
</html>`

		w.Write([]byte(fmt.Sprintf(template, apiCfg.fileserverHits.Load())))
	}

	resetHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte(fmt.Sprintf("Hits reset from: %v", apiCfg.fileserverHits.Load())))
		apiCfg.fileserverHits.Store(0)
	}

	serveMux.HandleFunc("GET /api/healthz", healthHandler)
	serveMux.HandleFunc("GET /admin/metrics", hitsHandler)
	serveMux.HandleFunc("POST /admin/reset", resetHandler)

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
