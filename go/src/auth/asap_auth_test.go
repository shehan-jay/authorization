package auth

import (
	"net/http"
	"testing"
)

func TestASAPAuth(t *testing.T) {
	// Create a new ASAPAuth instance with test credentials
	auth := NewASAPAuth("test-issuer", "test-audience", []byte("test-private-key"))

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid ASAP token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer test-asap-token",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid ASAP token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer invalid-asap-token",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Missing Authorization header",
			Request: CreateTestRequest("GET", nil),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Malformed Authorization header",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Invalid Authorization scheme",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Basic dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ=",
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

func TestASAPAuthGetType(t *testing.T) {
	auth := NewASAPAuth("issuer", "audience", []byte("private-key"))
	if auth.GetType() != "asap" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "asap")
	}
} 