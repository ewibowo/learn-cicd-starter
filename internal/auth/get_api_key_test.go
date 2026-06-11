package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError bool
		errorType     error
	}{
		{
			name: "valid API key",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey test-key-12345")
				return h
			}(),
			expectedKey:   "test-key-12345",
			expectedError: false,
		},
		{
			name:          "missing authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: true,
			errorType:     ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header - no ApiKey prefix",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "Bearer test-key")
				return h
			}(),
			expectedKey:   "",
			expectedError: true,
		},
		{
			name: "malformed header - missing key",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey")
				return h
			}(),
			expectedKey:   "",
			expectedError: true,
		},
		{
			name: "valid API key with special characters",
			headers: func() http.Header {
				h := http.Header{}
				h.Set("Authorization", "ApiKey abc123-_xyz789")
				return h
			}(),
			expectedKey:   "abc123-_xyz789",
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.expectedError {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				if tt.errorType != nil && err != tt.errorType {
					t.Errorf("expected error %v, got %v", tt.errorType, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if key != tt.expectedKey {
					t.Errorf("expected key %q, got %q", tt.expectedKey, key)
				}
			}
		})
	}
}
