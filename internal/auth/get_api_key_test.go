package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantKey    string
		wantErr    error
	}{
		{
			name:       "valid API key",
			authHeader: "ApiKey abc123",
			wantKey:    "abc123",
			wantErr:    nil,
		},
		{
			name:       "missing authorization header",
			authHeader: "",
			wantKey:    "",
			wantErr:    ErrNoAuthHeaderIncluded,
		},
		{
			name:       "malformed authorization header",
			authHeader: "Bearer abc123",
			wantKey:    "",
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name:       "missing API key",
			authHeader: "ApiKey",
			wantKey:    "",
			wantErr:    errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}

			gotKey, err := GetAPIKey(headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q",
					gotKey, tt.wantKey)
			}

			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("GetAPIKey() error = %v, want nil", err)
				}
			} else if err == nil {
				t.Errorf("GetAPIKey() error = nil, want %v", tt.wantErr)
			} else if tt.wantErr == ErrNoAuthHeaderIncluded {
				if err != ErrNoAuthHeaderIncluded {
					t.Errorf("GetAPIKey() error = %v, want %v",
						err, tt.wantErr)
				}
			} else if err.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v",
					err, tt.wantErr)
			}
		})
	}
}
