package auth

import (
	"net/http"
	"testing"
)

func TestHawkAuth(t *testing.T) {
	// Create a new HawkAuth instance with test credentials
	auth := NewHawkAuth(map[string]string{
		"test-hawk-id": "test-hawk-key",
	})

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid Hawk credentials",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Hawk id=\"test-hawk-id\"," +
					"ts=\"1234567890\"," +
					"nonce=\"test-nonce\"," +
					"mac=\"test-mac\"," +
					"hash=\"test-hash\"",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid Hawk ID",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Hawk id=\"wrong-hawk-id\"," +
					"ts=\"1234567890\"," +
					"nonce=\"test-nonce\"," +
					"mac=\"test-mac\"," +
					"hash=\"test-hash\"",
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
				"Authorization": "Hawk",
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

func TestHawkAuthGetType(t *testing.T) {
	auth := NewHawkAuth(map[string]string{"hawk-id": "hawk-key"})
	if auth.GetType() != "hawk" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "hawk")
	}
} 