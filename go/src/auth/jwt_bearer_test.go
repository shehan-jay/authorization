package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
)

func TestJWTBearer(t *testing.T) {
	// Create a new JWT Bearer instance with a secret key
	secretKey := []byte("your-secret-key")
	auth := NewJWTBearer(secretKey)

	// Create a valid JWT token
	validToken := createTestJWT(t, secretKey, time.Now().Add(time.Hour))

	// Create an expired JWT token
	expiredToken := createTestJWT(t, secretKey, time.Now().Add(-time.Hour))

	// Create a token with invalid signature
	invalidToken := createTestJWT(t, []byte("wrong-secret-key"), time.Now().Add(time.Hour))

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid JWT token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer " + validToken,
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Expired JWT token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer " + expiredToken,
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Invalid signature",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer " + invalidToken,
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name:           "Missing token",
			Request:        CreateTestRequest("GET", nil),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Malformed header",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			RunAuthTest(t, auth, tc)
		})
	}
}

func TestJWTBearerGetType(t *testing.T) {
	auth := NewJWTBearer([]byte("secret"))
	if auth.GetType() != "jwt" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "jwt")
	}
}

// Helper function to create a test JWT token
func createTestJWT(t *testing.T, secretKey []byte, expiration time.Time) string {
	t.Helper()

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": expiration.Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		t.Fatalf("Failed to create test JWT: %v", err)
	}

	return tokenString
} 