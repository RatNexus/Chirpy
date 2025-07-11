package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func readJSONRequest[T any](r *http.Request, jsonData *T) error {
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(jsonData)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	dat, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	w.WriteHeader(code)
	w.Write(dat)
	return nil
}

func respondWithError(w http.ResponseWriter, code int, msg string) error {
	return respondWithJSON(w, code, struct {
		Error string `json:"error"`
	}{Error: msg})
}

func contains(slice []string, word string) bool {
	for _, v := range slice {
		if v == word {
			return true
		}
	}
	return false
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

	validateChirpHandler := func(w http.ResponseWriter, r *http.Request) {
		type requestStruct struct {
			Body string `json:"body"`
		}
		type cleanedStruct struct {
			CleanedBody string `json:"cleaned_body"`
		}
		type validStruct struct {
			Valid bool `json:"valid"`
		}

		requestData := requestStruct{}
		err := readJSONRequest(r, &requestData)
		if err != nil {
			respondWithError(w, 400, "Something went wrong")
			return
		}

		if len(requestData.Body) > 140 {
			respondWithError(w, 400, "Chirp is too long")
			return
		}

		body := strings.Split(requestData.Body, " ")
		profanities := []string{"kerfuffle", "sharbert", "fornax"}
		for i := range body {
			if contains(profanities, strings.ToLower(body[i])) {
				body[i] = "****"
			}
		}

		joined := strings.Join(body, " ")
		respondWithJSON(w, 200, &cleanedStruct{CleanedBody: joined})
	}

	serveMux.HandleFunc("GET /api/healthz", healthHandler)
	serveMux.HandleFunc("GET /admin/metrics", hitsHandler)
	serveMux.HandleFunc("POST /admin/reset", resetHandler)
	serveMux.HandleFunc("POST /api/validate_chirp", validateChirpHandler)

	server := &http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	log.Print("Start server on http://localhost:8080/app")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
	log.Print("Server exited with no errors.")
}
