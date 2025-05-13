package auth

import (
	"net/http"
	"testing"
)

func TestOAuth1(t *testing.T) {
	// Create a new OAuth1 instance with test credentials
	auth := NewOAuth1(
		"test-consumer-key",
		"test-consumer-secret",
		"test-token",
		"test-token-secret",
	)

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid OAuth1 signature",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "OAuth oauth_consumer_key=\"test-consumer-key\"," +
					"oauth_nonce=\"test-nonce\"," +
					"oauth_signature=\"test-signature\"," +
					"oauth_signature_method=\"HMAC-SHA1\"," +
					"oauth_timestamp=\"1234567890\"," +
					"oauth_token=\"test-token\"," +
					"oauth_version=\"1.0\"",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid consumer key",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "OAuth oauth_consumer_key=\"wrong-key\"," +
					"oauth_nonce=\"test-nonce\"," +
					"oauth_signature=\"test-signature\"," +
					"oauth_signature_method=\"HMAC-SHA1\"," +
					"oauth_timestamp=\"1234567890\"," +
					"oauth_token=\"test-token\"," +
					"oauth_version=\"1.0\"",
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
				"Authorization": "OAuth",
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

func TestOAuth1GetType(t *testing.T) {
	auth := NewOAuth1("key", "secret", "token", "token-secret")
	if auth.GetType() != "oauth1" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "oauth1")
	}
} 