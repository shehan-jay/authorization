package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestCase represents a test case for authentication
type TestCase struct {
	Name           string
	Request        *http.Request
	ExpectedStatus int
	ExpectedError  bool
}

// RunAuthTest runs a test case for an authentication method
func RunAuthTest(t *testing.T, auth Authenticator, tc TestCase) {
	t.Helper()

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
	authHandler.ServeHTTP(rr, tc.Request)

	// Check the status code
	if status := rr.Code; status != tc.ExpectedStatus {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, tc.ExpectedStatus)
	}

	// Check if authentication error occurred
	if tc.ExpectedError {
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("expected unauthorized status, got %v", rr.Code)
		}
	}
}

// CreateTestRequest creates a test request with the given method and headers
func CreateTestRequest(method string, headers map[string]string) *http.Request {
	req := httptest.NewRequest(method, "/api/secure", nil)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return req
} 