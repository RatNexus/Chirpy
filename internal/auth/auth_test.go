package auth

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "mypassword123",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  false,
		},
		{
			name:     "password with special characters",
			password: "p@ssw0rd!#$%",
			wantErr:  false,
		},
		{
			name:     "unicode password",
			password: "пароль123",
			wantErr:  false,
		},
		{
			// bcrypt has a maximum input length of 72 bytes
			name:     "long password should fail",
			password: strings.Repeat("a", 73),
			wantErr:  true,
		},
		{
			// Testing extremely long passwords to ensure proper error handling
			name:     "extremely long password (should fail)",
			password: strings.Repeat("a", 1000),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)

			if tt.wantErr {
				if err == nil {
					t.Errorf("HashPassword() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("HashPassword() unexpected error: %v", err)
				return
			}

			if hash == "" {
				t.Error("HashPassword() returned empty hash")
			}

			// Verify the hash has the correct bcrypt format prefix
			if !strings.HasPrefix(hash, "$2a$") && !strings.HasPrefix(hash, "$2b$") {
				t.Errorf("HashPassword() hash doesn't have bcrypt prefix: %s", hash)
			}

			// Verify the generated hash can be used to validate the original password
			if err := CheckPasswordHash(tt.password, hash); err != nil {
				t.Errorf("HashPassword() generated hash that doesn't validate: %v", err)
			}
		})
	}
}

func TestHashPasswordConsistency(t *testing.T) {
	password := "testpassword"

	// Generate two hashes for the same password
	hash1, err1 := HashPassword(password)
	hash2, err2 := HashPassword(password)

	if err1 != nil || err2 != nil {
		t.Fatalf("HashPassword() failed: %v, %v", err1, err2)
	}

	// salty - Hashes should be different due to bcrypt's built-in salt
	if hash1 == hash2 {
		t.Error("HashPassword() should generate different hashes for same password")
	}

	// Both hashes should validate the same original password
	if err := CheckPasswordHash(password, hash1); err != nil {
		t.Errorf("First hash doesn't validate: %v", err)
	}

	if err := CheckPasswordHash(password, hash2); err != nil {
		t.Errorf("Second hash doesn't validate: %v", err)
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "testpassword123"
	// Create a valid hash to test against
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to generate test hash: %v", err)
	}

	tests := []struct {
		name     string
		password string
		hash     string
		wantErr  bool
	}{
		{
			name:     "correct password",
			password: password,
			hash:     hash,
			wantErr:  false,
		},
		{
			name:     "incorrect password",
			password: "wrongpassword",
			hash:     hash,
			wantErr:  true,
		},
		{
			// Empty password should not match a hash created from non-empty password
			name:     "empty password with valid hash",
			password: "",
			hash:     hash,
			wantErr:  true,
		},
		{
			name:     "valid password with empty hash",
			password: password,
			hash:     "",
			wantErr:  true,
		},
		{
			name:     "invalid hash format",
			password: password,
			hash:     "invalid-hash",
			wantErr:  true,
		},
		{
			// Password comparison is case-sensitive
			name:     "case sensitive password",
			password: "TESTPASSWORD123",
			hash:     hash,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckPasswordHash(tt.password, tt.hash)

			if tt.wantErr {
				if err == nil {
					t.Error("CheckPasswordHash() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("CheckPasswordHash() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCheckPasswordHashWithEmptyPassword(t *testing.T) {
	// Create a hash specifically for an empty password
	emptyHash, err := HashPassword("")
	if err != nil {
		t.Fatalf("Failed to hash empty password: %v", err)
	}

	// Empty password should validate against its own hash
	if err := CheckPasswordHash("", emptyHash); err != nil {
		t.Errorf("Empty password should validate against its hash: %v", err)
	}

	// Non-empty password should not validate against empty password hash
	if err := CheckPasswordHash("nonempty", emptyHash); err == nil {
		t.Error("Non-empty password should not validate against empty password hash")
	}
}

func TestPasswordHashingRoundTrip(t *testing.T) {
	// Test various password types to ensure round-trip functionality
	passwords := []string{
		"simple",
		"complex!@#$%^&*()",
		"with spaces and numbers 123",
		"unicode: 你好世界",
		strings.Repeat("long", 15), // 60 characters
	}

	for _, password := range passwords {
		// Truncate password name for test readability
		t.Run("password_"+password[:min(10, len(password))], func(t *testing.T) {
			// Hash the password
			hash, err := HashPassword(password)
			if err != nil {
				t.Fatalf("HashPassword() failed: %v", err)
			}

			// Verify the password validates against its hash
			if err := CheckPasswordHash(password, hash); err != nil {
				t.Errorf("Password validation failed: %v", err)
			}

			// Verify a wrong password doesn't validate
			wrongPassword := password + "wrong"
			if err := CheckPasswordHash(wrongPassword, hash); err == nil {
				t.Error("Wrong password should not validate")
			}
		})
	}
}

// ------------------------------------

func TestMakeJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"
	expiresIn := time.Hour

	tests := []struct {
		name        string
		userID      uuid.UUID
		tokenSecret string
		expiresIn   time.Duration
		wantErr     bool
	}{
		{
			name:        "valid token creation",
			userID:      userID,
			tokenSecret: tokenSecret,
			expiresIn:   expiresIn,
			wantErr:     false,
		},
		{
			// JWT library allows empty secrets (though not recommended for production)
			name:        "empty secret",
			userID:      userID,
			tokenSecret: "",
			expiresIn:   expiresIn,
			wantErr:     false, // JWT allows empty secret
		},
		{
			// Token with zero expiration creates an immediately expired token
			name:        "zero expiration",
			userID:      userID,
			tokenSecret: tokenSecret,
			expiresIn:   0,
			wantErr:     false,
		},
		{
			// Negative expiration creates a token that expired in the past
			name:        "negative expiration",
			userID:      userID,
			tokenSecret: tokenSecret,
			expiresIn:   -time.Hour,
			wantErr:     false, // Creates expired token
		},
		{
			name:        "nil UUID",
			userID:      uuid.Nil,
			tokenSecret: tokenSecret,
			expiresIn:   expiresIn,
			wantErr:     false,
		},
		{
			name:        "very long secret",
			userID:      userID,
			tokenSecret: strings.Repeat("a", 1000),
			expiresIn:   expiresIn,
			wantErr:     false,
		},
		{
			name:        "very long expiration",
			userID:      userID,
			tokenSecret: tokenSecret,
			expiresIn:   time.Hour * 24 * 365 * 10, // 10 years
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := MakeJWT(tt.userID, tt.tokenSecret, tt.expiresIn)

			if tt.wantErr {
				if err == nil {
					t.Error("MakeJWT() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("MakeJWT() unexpected error: %v", err)
				return
			}

			if token == "" {
				t.Error("MakeJWT() returned empty token")
			}

			// Verify JWT structure: header.payload.signature
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				t.Errorf("MakeJWT() token doesn't have 3 parts: %d", len(parts))
			}
		})
	}
}

func TestMakeJWTClaims(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret"
	expiresIn := time.Hour

	token, err := MakeJWT(userID, tokenSecret, expiresIn)

	if err != nil {
		t.Fatalf("MakeJWT() failed: %v", err)
	}

	// Parse the token to verify its claims
	parsedToken, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(tokenSecret), nil
		})

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	claims := parsedToken.Claims.(*jwt.RegisteredClaims)

	// Verify the issuer claim is set correctly
	if claims.Issuer != "Chirpy" {
		t.Errorf("Expected issuer 'Chirpy', got '%s'", claims.Issuer)
	}

	// Verify the subject claim contains the user ID
	if claims.Subject != userID.String() {
		t.Errorf("Expected subject '%s', got '%s'", userID.String(), claims.Subject)
	}

	// Verify expiration time is calculated correctly from issued time + duration
	expectedExpiry := claims.IssuedAt.Time.Add(expiresIn)
	if !claims.ExpiresAt.Time.Equal(expectedExpiry) {
		t.Errorf("Expected expiry %v, got %v", expectedExpiry, claims.ExpiresAt.Time)
	}
}

func TestValidateJWT(t *testing.T) {
	userID := uuid.New()
	tokenSecret := "test-secret-key"

	// Create a valid token for testing
	validToken, err := MakeJWT(userID, tokenSecret, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Create an expired token for testing
	expiredToken, err := MakeJWT(userID, tokenSecret, -time.Hour)
	if err != nil {
		t.Fatalf("Failed to create expired token: %v", err)
	}

	tests := []struct {
		name        string
		tokenString string
		tokenSecret string
		wantUserID  uuid.UUID
		wantErr     bool
	}{
		{
			name:        "valid token",
			tokenString: validToken,
			tokenSecret: tokenSecret,
			wantUserID:  userID,
			wantErr:     false,
		},
		{
			// Token signed with different secret should fail validation
			name:        "wrong secret",
			tokenString: validToken,
			tokenSecret: "wrong-secret",
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			// Expired tokens should be rejected
			name:        "expired token",
			tokenString: expiredToken,
			tokenSecret: tokenSecret,
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			name:        "empty token",
			tokenString: "",
			tokenSecret: tokenSecret,
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			// Malformed JWT structure should be rejected
			name:        "malformed token",
			tokenString: "invalid.token.here",
			tokenSecret: tokenSecret,
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			// Tampering with token signature should cause validation failure
			name:        "token with invalid signature",
			tokenString: validToken[:len(validToken)-5] + "wrong",
			tokenSecret: tokenSecret,
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
		{
			// Using empty secret to validate token created with non-empty secret
			name:        "empty secret with valid token",
			tokenString: validToken,
			tokenSecret: "",
			wantUserID:  uuid.Nil,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserID, err := ValidateJWT(tt.tokenString, tt.tokenSecret)

			if tt.wantErr {
				if err == nil {
					t.Error("ValidateJWT() expected error but got none")
				}
				// On error, should return nil UUID
				if gotUserID != uuid.Nil {
					t.Errorf("ValidateJWT() expected nil UUID on error, got %v", gotUserID)
				}
				return
			}

			if err != nil {
				t.Errorf("ValidateJWT() unexpected error: %v", err)
				return
			}

			if gotUserID != tt.wantUserID {
				t.Errorf("ValidateJWT() got userID %v, want %v", gotUserID, tt.wantUserID)
			}
		})
	}
}

func TestValidateJWTWithInvalidSubject(t *testing.T) {
	tokenSecret := "test-secret"

	// Manually create a token with an invalid UUID string as subject
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "Chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour).UTC()),
		Subject:   "invalid-uuid-string",
	})

	tokenString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Should fail when trying to parse invalid UUID from subject
	userID, err := ValidateJWT(tokenString, tokenSecret)
	if err == nil {
		t.Error("ValidateJWT() expected error for invalid UUID subject")
	}
	if userID != uuid.Nil {
		t.Errorf("ValidateJWT() expected nil UUID, got %v", userID)
	}
}

func TestJWTRoundTrip(t *testing.T) {
	// Test complete create -> validate cycle with various parameters
	testCases := []struct {
		name      string
		userID    uuid.UUID
		secret    string
		expiresIn time.Duration
	}{
		{
			name:      "standard case",
			userID:    uuid.New(),
			secret:    "standard-secret",
			expiresIn: time.Hour,
		},
		{
			name:      "nil UUID",
			userID:    uuid.Nil,
			secret:    "secret-for-nil",
			expiresIn: time.Minute * 30,
		},
		{
			name:      "long secret",
			userID:    uuid.New(),
			secret:    strings.Repeat("long-secret-", 10),
			expiresIn: time.Hour * 24,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create token
			token, err := MakeJWT(tc.userID, tc.secret, tc.expiresIn)
			if err != nil {
				t.Fatalf("MakeJWT() failed: %v", err)
			}

			// Validate token and extract user ID
			validatedUserID, err := ValidateJWT(token, tc.secret)
			if err != nil {
				t.Fatalf("ValidateJWT() failed: %v", err)
			}

			// Verify round-trip preserves user ID
			if validatedUserID != tc.userID {
				t.Errorf("Round trip failed: got %v, want %v",
					validatedUserID, tc.userID)
			}
		})
	}
}

func TestJWTTimingEdgeCases(t *testing.T) {
	userID := uuid.New()
	secret := "timing-test-secret"

	// Test token that expires very quickly
	t.Run("token expires exactly now", func(t *testing.T) {
		// Create token with 1ms expiration
		token, err := MakeJWT(userID, secret, time.Millisecond)
		if err != nil {
			t.Fatalf("MakeJWT() failed: %v", err)
		}

		// Wait for token to expire
		time.Sleep(time.Millisecond * 2)

		// Should fail validation due to expiration
		_, err = ValidateJWT(token, secret)
		if err == nil {
			t.Error("Expected expired token to fail validation")
		}
	})

	// Test extremely short expiration times
	t.Run("token with very short expiration", func(t *testing.T) {
		token, err := MakeJWT(userID, secret, time.Nanosecond)
		if err != nil {
			t.Fatalf("MakeJWT() failed: %v", err)
		}

		// This test is timing-dependent - token might already be expired
		_, err = ValidateJWT(token, secret)
		if err == nil {
			t.Log("Token with nanosecond expiration still valid (timing dependent)")
		}
	})
}

// -----------------------------------------

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		expectedToken string
		expectedError string
		wantErr       bool
	}{
		{
			name:          "valid bearer token",
			authorization: "Bearer abc123token",
			expectedToken: "abc123token",
			wantErr:       false,
		},
		{
			name:          "valid bearer token with spaces",
			authorization: "Bearer token with spaces",
			expectedToken: "token with spaces",
			wantErr:       false,
		},
		{
			name:          "valid bearer token with special characters",
			authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantErr:       false,
		},
		{
			name:          "bearer token with just Bearer and space",
			authorization: "Bearer ",
			expectedToken: "",
			wantErr:       false,
		},
		{
			name:          "bearer token with minimal content",
			authorization: "Bearer x",
			expectedToken: "x",
			wantErr:       false,
		},
		{
			name:          "empty authorization header",
			authorization: "",
			expectedError: "no authorization token in given header",
			wantErr:       true,
		},
		{
			name:          "missing Bearer prefix",
			authorization: "Basic abc123",
			expectedError: "authorization token has no Bearer prefix",
			wantErr:       true,
		},
		{
			name:          "case sensitive Bearer prefix",
			authorization: "bearer abc123",
			expectedError: "authorization token has no Bearer prefix",
			wantErr:       true,
		},
		{
			name:          "Bearer without space",
			authorization: "Bearerabc123",
			expectedError: "authorization token has no Bearer prefix",
			wantErr:       true,
		},
		{
			name:          "partial Bearer prefix",
			authorization: "Bear abc123",
			expectedError: "authorization token has no Bearer prefix",
			wantErr:       true,
		},
		{
			name:          "Bearer with extra spaces",
			authorization: "Bearer  token_with_extra_space",
			expectedToken: " token_with_extra_space",
			wantErr:       false,
		},
		{
			name:          "Bearer with tab character",
			authorization: "Bearer\ttoken_with_tab",
			expectedError: "authorization token has no Bearer prefix",
			wantErr:       true,
		},
		{
			name:          "authorization with only Bearer",
			authorization: "Bearer",
			expectedError: "authorization token has no Bearer prefix",
			wantErr:       true,
		},
		{
			name:          "authorization with Bearer and newline",
			authorization: "Bearer token\nwith\nnewlines",
			expectedToken: "token\nwith\nnewlines",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create HTTP headers
			headers := make(http.Header)
			if tt.authorization != "" {
				headers.Set("Authorization", tt.authorization)
			}

			// Call the function
			token, err := GetBearerToken(headers)

			// Check error expectations
			if tt.wantErr {
				if err == nil {
					t.Errorf("GetBearerToken() expected error but got none")
					return
				}
				if tt.expectedError != "" && err.Error() != tt.expectedError {
					t.Errorf("GetBearerToken() error = %v, want %v", err.Error(), tt.expectedError)
				}
				// Token should be empty on error
				if token != "" {
					t.Errorf("GetBearerToken() expected empty token on error, got %v", token)
				}
				return
			}

			// Check success case
			if err != nil {
				t.Errorf("GetBearerToken() unexpected error: %v", err)
				return
			}

			if token != tt.expectedToken {
				t.Errorf("GetBearerToken() token = %v, want %v", token, tt.expectedToken)
			}
		})
	}
}

func TestGetBearerTokenWithMultipleHeaders(t *testing.T) {
	// Test with multiple authorization headers (should use the first one)
	headers := make(http.Header)
	headers.Add("Authorization", "Bearer first_token")
	headers.Add("Authorization", "Bearer second_token")

	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("GetBearerToken() unexpected error: %v", err)
	}

	// Should return the first token
	expectedToken := "first_token"
	if token != expectedToken {
		t.Errorf("GetBearerToken() with multiple headers got %v, want %v", token, expectedToken)
	}
}

func TestGetBearerTokenCaseInsensitiveHeader(t *testing.T) {
	// Test that header name is case-insensitive (HTTP standard)
	testCases := []string{
		"Authorization",
		"authorization",
		"AUTHORIZATION",
		"AuThOrIzAtIoN",
	}

	expectedToken := "test_token"
	authValue := "Bearer " + expectedToken

	for _, headerName := range testCases {
		t.Run("header_case_"+headerName, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set(headerName, authValue)

			token, err := GetBearerToken(headers)
			if err != nil {
				t.Errorf("GetBearerToken() with header %s failed: %v", headerName, err)
				return
			}

			if token != expectedToken {
				t.Errorf("GetBearerToken() with header %s got %v, want %v", headerName, token, expectedToken)
			}
		})
	}
}

func TestGetBearerTokenWithOtherHeaders(t *testing.T) {
	// Test that other headers don't interfere
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set("User-Agent", "test-agent")
	headers.Set("Authorization", "Bearer my_token")
	headers.Set("Accept", "application/json")

	token, err := GetBearerToken(headers)
	if err != nil {
		t.Fatalf("GetBearerToken() unexpected error: %v", err)
	}

	expectedToken := "my_token"
	if token != expectedToken {
		t.Errorf("GetBearerToken() got %v, want %v", token, expectedToken)
	}
}

func TestGetBearerTokenEmptyHeaders(t *testing.T) {
	// Test with completely empty headers
	headers := make(http.Header)

	token, err := GetBearerToken(headers)
	if err == nil {
		t.Error("GetBearerToken() expected error with empty headers")
		return
	}

	expectedError := "no authorization token in given header"
	if err.Error() != expectedError {
		t.Errorf("GetBearerToken() error = %v, want %v", err.Error(), expectedError)
	}

	if token != "" {
		t.Errorf("GetBearerToken() expected empty token, got %v", token)
	}
}

func TestGetBearerTokenNilHeaders(t *testing.T) {
	// Test with nil headers (should not panic)
	var headers http.Header

	token, err := GetBearerToken(headers)
	if err == nil {
		t.Error("GetBearerToken() expected error with nil headers")
		return
	}

	expectedError := "no authorization token in given header"
	if err.Error() != expectedError {
		t.Errorf("GetBearerToken() error = %v, want %v", err.Error(), expectedError)
	}

	if token != "" {
		t.Errorf("GetBearerToken() expected empty token, got %v", token)
	}
}

// Test the edge case behavior with whitespace
func TestGetBearerTokenWhitespaceHandling(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		expectedToken string
		wantErr       bool
	}{
		{
			name:          "leading spaces in token",
			authorization: "Bearer   token_with_leading_spaces",
			expectedToken: "  token_with_leading_spaces",
			wantErr:       false,
		},
		{
			name:          "trailing spaces in token",
			authorization: "Bearer token_with_trailing_spaces   ",
			expectedToken: "token_with_trailing_spaces   ",
			wantErr:       false,
		},
		{
			name:          "token with internal spaces",
			authorization: "Bearer token with internal spaces",
			expectedToken: "token with internal spaces",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			headers.Set("Authorization", tt.authorization)

			token, err := GetBearerToken(headers)

			if tt.wantErr {
				if err == nil {
					t.Error("GetBearerToken() expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("GetBearerToken() unexpected error: %v", err)
				return
			}

			if token != tt.expectedToken {
				t.Errorf("GetBearerToken() token = %q, want %q", token, tt.expectedToken)
			}
		})
	}
}
