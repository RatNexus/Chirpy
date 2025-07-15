package main

import (
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
}

type requestStruct struct {
	Body string `json:"body"`
}

type User struct {
	ID         uuid.UUID `json:"id"`
	Created_at time.Time `json:"created_at"`
	Updated_at time.Time `json:"updated_at"`
	Email      string    `json:"email"`
}

type Chirp struct {
	ID         uuid.UUID `json:"id"`
	Created_at time.Time `json:"created_at"`
	Updated_at time.Time `json:"updated_at"`
	Body       string    `json:"body"`
	User_id    uuid.UUID `json:"user_id"`
}

type createChirpReq struct {
	Body    string `json:"body"`
	User_id string `json:"user_id"`
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
	log.Print(msg)
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

func ironChirp(dbChirp database.Chirp) Chirp {
	return Chirp{
		ID:         dbChirp.ID,
		Created_at: dbChirp.CreatedAt.Time,
		Updated_at: dbChirp.CreatedAt.Time,
		Body:       dbChirp.Body,
		User_id:    dbChirp.UserID,
	}
}

func ironChirps(dbChirps []database.Chirp) []Chirp {
	smoothChirps := make([]Chirp, len(dbChirps))
	for i := range dbChirps {
		smoothChirps[i] = ironChirp(dbChirps[i])
	}

	return smoothChirps
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	db, err := sql.Open("postgres", dbURL)
	dbQueries := database.New(db)

	if err != nil {
		log.Fatal("Could not open postres db")
	}
	defer db.Close()

	serveMux := http.NewServeMux()
	apiCfg := &apiConfig{}
	apiCfg.fileserverHits.Store(0)
	apiCfg.dbQueries = dbQueries
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
		if platform != "dev" {
			respondWithError(w, 403, "Forbidden")
			return
		}
		apiCfg.fileserverHits.Store(0)
		apiCfg.dbQueries.DeleteAllUsers(r.Context())

		msg := fmt.Sprintf("Users Deleted. Hits reset from: %v", apiCfg.fileserverHits.Load())
		respondWithJSON(w, 200, requestStruct{Body: msg})
	}

	createChirpHandler := func(w http.ResponseWriter, r *http.Request) {
		createChirpReqData := createChirpReq{}
		err := readJSONRequest(r, &createChirpReqData)
		if err != nil {
			respondWithError(w, 400, "Something went wrong")
			return
		}

		if len(createChirpReqData.Body) > 140 {
			respondWithError(w, 400, "Chirp is too long")
			return
		}

		body := strings.Split(createChirpReqData.Body, " ")
		profanities := []string{"kerfuffle", "sharbert", "fornax"}
		for i := range body {
			if contains(profanities, strings.ToLower(body[i])) {
				body[i] = "****"
			}
		}
		joined := strings.Join(body, " ")

		user_uuid, err := uuid.Parse(createChirpReqData.User_id)
		if err != nil {
			respondWithError(w, 400, "Something went wrong")
			return
		}

		chirp, err := apiCfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{
			Body:   joined,
			UserID: user_uuid,
		})
		if err != nil {
			respondWithError(w, 400, "Something went wrong")
			return
		}
		outChirp := ironChirp(chirp)
		respondWithJSON(w, 201, &outChirp)
	}

	addUserHandler := func(w http.ResponseWriter, r *http.Request) {
		type emailStruct struct {
			Email string `json:"email"`
		}

		gotMail := &emailStruct{}
		readJSONRequest(r, gotMail)

		user, err := apiCfg.dbQueries.CreateUser(r.Context(), gotMail.Email)
		if err != nil {
			prt := fmt.Sprintf("Failed to create user. Err: %e", err)
			log.Print(prt)
			respondWithError(w, 400, prt)
		}
		userSt := User{
			ID:         user.ID,
			Email:      user.Email,
			Created_at: user.CreatedAt,
			Updated_at: user.UpdatedAt,
		}
		respondWithJSON(w, 201, &userSt)
	}

	getChirpsHandler := func(w http.ResponseWriter, r *http.Request) {
		chirps, err := apiCfg.dbQueries.GetAllChirps(r.Context())
		if err != nil {
			respondWithError(w, 400, "Something went wrong")
			return
		}

		smoothChirps := ironChirps(chirps)
		respondWithJSON(w, 200, smoothChirps)

	}

	serveMux.HandleFunc("GET /api/healthz", healthHandler)
	serveMux.HandleFunc("POST /api/users", addUserHandler)
	serveMux.HandleFunc("POST /api/chirps", createChirpHandler)
	serveMux.HandleFunc("GET /api/chirps", getChirpsHandler)

	serveMux.HandleFunc("GET /admin/metrics", hitsHandler)
	serveMux.HandleFunc("POST /admin/reset", resetHandler)

	server := &http.Server{
		Addr:    ":8080",
		Handler: serveMux,
	}

	log.Print("Start server on http://localhost:8080/app")
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
	log.Print("Server exited with no errors.")
}
