package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name           string
		headers        http.Header
		expectedAPIKey string
		expectedError  error
	}{
		{
			name:           "Valid API key",
			headers:        http.Header{"Authorization": {"ApiKey myApiKey123"}},
			expectedAPIKey: "myApiKey123",
			expectedError:  nil,
		},
		{
			name:           "No authorization header",
			headers:        http.Header{},
			expectedAPIKey: "",
			expectedError:  ErrNoAuthHeaderIncluded,
		},
		{
			name:           "Malformed authorization header",
			headers:        http.Header{"Authorization": {"InvalidAuth myApiKey123"}},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
		{
			name:           "Authorization header without API key",
			headers:        http.Header{"Authorization": {"ApiKey"}},
			expectedAPIKey: "",
			expectedError:  errors.New("malformed authorization header"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(test.headers)
			if apiKey != test.expectedAPIKey {
				t.Errorf("expected API key %v, got %v", test.expectedAPIKey, apiKey)
			}
			if err != nil && err.Error() != test.expectedError.Error() {
				t.Errorf("expected error %v, got %v", test.expectedError, err)
			}
			if err == nil && test.expectedError != nil {
				t.Errorf("expected error %v, got nil", test.expectedError)
			}
		})
	}
}
