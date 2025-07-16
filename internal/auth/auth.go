package auth

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"crypto/rand"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "Chirpy",
		IssuedAt:  jwt.NewNumericDate(now.UTC()),
		ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn).UTC()),
		Subject:   userID.String(),
	})
	out, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return out, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})
	if err != nil {
		return uuid.Nil, err
	}

	subject, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.Nil, err
	}

	user_id, err := uuid.Parse(subject)
	if err != nil {
		return uuid.Nil, err
	}

	return user_id, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	authority := headers.Get("Authorization")
	if authority == "" {
		return "", fmt.Errorf("no authorization token in given header")
	}

	if !strings.HasPrefix(authority, "Bearer ") {
		fmt.Print(authority)
		return "", fmt.Errorf("authorization token has no Bearer prefix")
	}
	//fmt.Print(authority)
	token_str := authority[7:]
	//fmt.Print(token_str)
	return token_str, nil
}

func MakeRefreshToken() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	dat := hex.EncodeToString(key)

	return dat, nil
}
