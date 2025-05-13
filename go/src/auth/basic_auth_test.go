package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBasicAuth(t *testing.T) {
	// Create a new BasicAuth instance
	auth := NewBasicAuth("admin", "password123")

	// Test cases
	tests := []struct {
		name           string
		username       string
		password       string
		expectedStatus int
	}{
		{
			name:           "Valid credentials",
			username:       "admin",
			password:       "password123",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Invalid username",
			username:       "wronguser",
			password:       "password123",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid password",
			username:       "admin",
			password:       "wrongpass",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Missing credentials",
			username:       "",
			password:       "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a test request
			req := httptest.NewRequest("GET", "/api/secure", nil)
			if tt.username != "" || tt.password != "" {
				req.SetBasicAuth(tt.username, tt.password)
			}

			// Create a response recorder
			rr := httptest.NewRecorder()

			// Create a test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Success"))
			})

			// Wrap the handler with authentication
			authHandler := RequiresAuth(auth)(handler)

			// Serve the request
			authHandler.ServeHTTP(rr, req)

			// Check the status code
			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.expectedStatus)
			}
		})
	}
}

func TestBasicAuthGetType(t *testing.T) {
	auth := NewBasicAuth("admin", "password123")
	if auth.GetType() != BasicAuth {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), BasicAuth)
	}
} 