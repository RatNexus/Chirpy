package main

import (
	"chirpy/internal/auth"
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

// ------------------------------

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	secret         string
	platform       string
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

type UserWithToken struct {
	User
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token"`
}

type JustToken struct {
	Token string `json:"token"`
}

type userEnter struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Chirp struct {
	ID         uuid.UUID `json:"id"`
	Created_at time.Time `json:"created_at"`
	Updated_at time.Time `json:"updated_at"`
	Body       string    `json:"body"`
	User_id    uuid.UUID `json:"user_id"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

// ------------------------------

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

// ------------------------------

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

// ------------------------------

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	w.Write([]byte("OK"))
}

func (apiCfg *apiConfig) hitsHandler(w http.ResponseWriter, r *http.Request) {
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

func (apiCfg *apiConfig) resetHandler(w http.ResponseWriter, r *http.Request) {
	if apiCfg.platform != "dev" {
		respondWithError(w, 403, "Forbidden")
		return
	}
	apiCfg.fileserverHits.Store(0)
	apiCfg.dbQueries.DeleteAllUsers(r.Context())

	msg := fmt.Sprintf("Users Deleted. Hits reset from: %v", apiCfg.fileserverHits.Load())
	respondWithJSON(w, 200, requestStruct{Body: msg})
}

func (apiCfg *apiConfig) createChirpHandler(w http.ResponseWriter, r *http.Request) {
	createChirpReqData := requestStruct{}
	err := readJSONRequest(r, &createChirpReqData)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	token_str, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
		return
	}

	user_uuid, err := auth.ValidateJWT(token_str, apiCfg.secret)
	if err != nil {
		respondWithError(w, 401, "Unauthorized")
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

func (apiCfg *apiConfig) addUserHandler(w http.ResponseWriter, r *http.Request) {
	userRegister := &userEnter{}
	readJSONRequest(r, userRegister)
	hashed_password, err := auth.HashPassword(userRegister.Password)
	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Failed to create user. Err: %e", err))
		return
	}

	user, err := apiCfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{
		Email:          userRegister.Email,
		HashedPassword: hashed_password,
	})

	if err != nil {
		respondWithError(w, 400, fmt.Sprintf("Failed to create user. Err: %e", err))
		return
	}
	userSt := User{
		ID:         user.ID,
		Email:      user.Email,
		Created_at: user.CreatedAt,
		Updated_at: user.UpdatedAt,
	}
	respondWithJSON(w, 201, &userSt)
}

func (apiCfg *apiConfig) getChirpsHandler(w http.ResponseWriter, r *http.Request) {
	chirps, err := apiCfg.dbQueries.GetAllChirps(r.Context())
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	smoothChirps := ironChirps(chirps)
	respondWithJSON(w, 200, smoothChirps)
}

func (apiCfg *apiConfig) getChirpHandler(w http.ResponseWriter, r *http.Request) {
	chirp_id := r.PathValue("chirpID")
	chirp_uuid, err := uuid.Parse(chirp_id)
	if chirp_id == "" || err != nil {
		respondWithError(w, 404, "Something went wrong")
		return
	}

	chirp, err := apiCfg.dbQueries.GetChirp(r.Context(), chirp_uuid)
	if err != nil {
		respondWithError(w, 404, "Something went wrong")
		return
	}

	respondWithJSON(w, 200, ironChirp(chirp))
}

func (apiCfg *apiConfig) loginUserHandler(w http.ResponseWriter, r *http.Request) {
	userLogIn := &userEnter{}
	readJSONRequest(r, userLogIn)

	user, err := apiCfg.dbQueries.GetUserByEmail(r.Context(), userLogIn.Email)
	if err != nil ||
		auth.CheckPasswordHash(userLogIn.Password, user.HashedPassword) != nil {
		respondWithError(w, 401, "Incorrect email or password")
		return
	}

	expiresIn := time.Duration(3600) * time.Second
	token, err := auth.MakeJWT(user.ID, apiCfg.secret, expiresIn)

	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	refresh_token, err := auth.MakeRefreshToken()
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}
	_, err = apiCfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		UserID: user.ID,
		Token:  refresh_token,
	})
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	userSt := UserWithToken{
		User: User{
			ID:         user.ID,
			Email:      user.Email,
			Created_at: user.CreatedAt,
			Updated_at: user.UpdatedAt,
		},
		Token:        token,
		RefreshToken: refresh_token,
	}
	respondWithJSON(w, 200, &userSt)
}

func (apiCfg *apiConfig) refreshTokenHandle(w http.ResponseWriter, r *http.Request) {
	tokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Something went wrong 1")
		return
	}

	user_uuid, err := apiCfg.dbQueries.GetRefreshToken(r.Context(), tokenStr)
	if err != nil {
		log.Print(err)
		respondWithError(w, 401, "Something went wrong 2")
		return
	}
	expiresIn := time.Duration(3600) * time.Second
	access_token, err := auth.MakeJWT(user_uuid, apiCfg.secret, expiresIn)
	if err != nil {
		respondWithError(w, 400, "Something went wrong 3")
		return
	}

	respondWithJSON(w, 200, JustToken{Token: access_token})
}

func (apiCfg *apiConfig) revokeTokenHandle(w http.ResponseWriter, r *http.Request) {
	tokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Something went wrong")
		return
	}

	_, err = apiCfg.dbQueries.RevokeToken(r.Context(), tokenStr)
	if err != nil {
		respondWithError(w, 401, "Something went wrong")
		return
	}

	respondWithJSON(w, 204, nil)
}

func (apiCfg *apiConfig) updateUserHandler(w http.ResponseWriter, r *http.Request) {
	userDat := &userEnter{}
	readJSONRequest(r, userDat)

	tokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Something went wrong")
		return
	}

	user_uuid, err := auth.ValidateJWT(tokenStr, apiCfg.secret)
	if err != nil {
		respondWithError(w, 401, "Something went wrong")
		return
	}

	hashed_password, err := auth.HashPassword(userDat.Password)
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	user, err := apiCfg.dbQueries.UpdateUser(r.Context(), database.UpdateUserParams{
		ID:             user_uuid,
		Email:          userDat.Email,
		HashedPassword: hashed_password,
	})
	if err != nil {
		respondWithError(w, 400, "Something went wrong")
		return
	}

	userStruct := User{
		ID:         user_uuid,
		Created_at: user.CreatedAt,
		Updated_at: user.UpdatedAt,
		Email:      user.Email,
	}

	respondWithJSON(w, 200, userStruct)
}

func (apiCfg *apiConfig) deleteChirpHandler(w http.ResponseWriter, r *http.Request) {
	tokenStr, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, 401, "Something went wrong")
		return
	}

	user_uuid, err := auth.ValidateJWT(tokenStr, apiCfg.secret)
	if err != nil {
		respondWithError(w, 403, "Something went wrong")
		return
	}

	chirp_id := r.PathValue("chirpID")
	chirp_uuid, err := uuid.Parse(chirp_id)
	if chirp_id == "" || err != nil {
		respondWithError(w, 404, "Something went wrong")
		return
	}

	one, err := apiCfg.dbQueries.CanBeDeleted(r.Context(), database.CanBeDeletedParams{
		ID:     chirp_uuid,
		UserID: user_uuid,
	})
	if err != nil || one != 1 {
		respondWithError(w, 403, "Something went wrong")
		return
	}

	err = apiCfg.dbQueries.DeleteChirp(r.Context(), database.DeleteChirpParams{
		ID:     chirp_uuid,
		UserID: user_uuid,
	})
	if err != nil {
		respondWithError(w, 404, "Something went wrong")
		return
	}

	respondWithJSON(w, 204, nil)
}

// ------------------------------

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatal("DB_URL must be set")
	}
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
	apiCfg.platform = os.Getenv("PLATFORM")
	if apiCfg.platform == "" {
		log.Fatal("PLATFORM must be set")
	}
	apiCfg.secret = os.Getenv("JWT_SECRET")
	if apiCfg.secret == "" {
		log.Fatal("JWT_SECRET environment variable is not set")
	}

	appHandler := http.StripPrefix("/app/", http.FileServer(http.Dir("./static/")))
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(appHandler))

	serveMux.HandleFunc("GET /api/healthz", healthHandler)
	serveMux.HandleFunc("POST /api/login", apiCfg.loginUserHandler)
	serveMux.HandleFunc("POST /api/refresh", apiCfg.refreshTokenHandle)
	serveMux.HandleFunc("POST /api/revoke", apiCfg.revokeTokenHandle)

	serveMux.HandleFunc("POST /api/users", apiCfg.addUserHandler)
	serveMux.HandleFunc("PUT /api/users", apiCfg.updateUserHandler)

	serveMux.HandleFunc("POST /api/chirps", apiCfg.createChirpHandler)
	serveMux.HandleFunc("GET /api/chirps", apiCfg.getChirpsHandler)
	serveMux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.getChirpHandler)
	serveMux.HandleFunc("DELETE /api/chirps/{chirpID}", apiCfg.deleteChirpHandler)

	serveMux.HandleFunc("GET /admin/metrics", apiCfg.hitsHandler)
	serveMux.HandleFunc("POST /admin/reset", apiCfg.resetHandler)

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
