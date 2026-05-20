package webhook

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeJWT builds a JWT-shaped string with the given JSON payload. The header
// and signature segments are placeholders — subjectFromJWT does not verify.
func makeJWT(payload string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString([]byte("placeholder"))
	return strings.Join([]string{header, body, sig}, ".")
}

func TestSubjectFromJWT(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		want    string
		wantErr bool
	}{
		{
			name:  "valid token with sub claim",
			token: makeJWT(`{"sub":"system:serviceaccount:kubescape:operator","iss":"kubernetes/serviceaccount"}`),
			want:  "system:serviceaccount:kubescape:operator",
		},
		{
			name:  "valid token with extra claims",
			token: makeJWT(`{"sub":"system:serviceaccount:ns:sa","aud":["api"],"exp":1234567890,"kubernetes.io":{"namespace":"ns","serviceaccount":{"name":"sa","uid":"abc"}}}`),
			want:  "system:serviceaccount:ns:sa",
		},
		{
			name:    "missing sub claim",
			token:   makeJWT(`{"iss":"kubernetes/serviceaccount"}`),
			wantErr: true,
		},
		{
			name:    "empty sub claim",
			token:   makeJWT(`{"sub":""}`),
			wantErr: true,
		},
		{
			name:    "not a JWT",
			token:   "not.a.jwt.token.extra",
			wantErr: true,
		},
		{
			name:    "too few segments",
			token:   "header.payload",
			wantErr: true,
		},
		{
			name:    "invalid base64 payload",
			token:   "header.!!!notbase64!!!.sig",
			wantErr: true,
		},
		{
			name:    "valid base64 but not JSON",
			token:   "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".sig",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := subjectFromJWT(tt.token)
			if (err != nil) != tt.wantErr {
				t.Fatalf("subjectFromJWT() err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("subjectFromJWT() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadSelfSubject(t *testing.T) {
	t.Run("reads valid token from file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "token")
		token := makeJWT(`{"sub":"system:serviceaccount:kubescape:operator"}`)
		if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
			t.Fatalf("write token: %v", err)
		}

		got, err := readSelfSubject(path)
		if err != nil {
			t.Fatalf("readSelfSubject() error: %v", err)
		}
		if got != "system:serviceaccount:kubescape:operator" {
			t.Errorf("got %q, want %q", got, "system:serviceaccount:kubescape:operator")
		}
	})

	t.Run("trims surrounding whitespace", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "token")
		token := makeJWT(`{"sub":"system:serviceaccount:ns:sa"}`)
		if err := os.WriteFile(path, []byte("\n  "+token+"\n"), 0o600); err != nil {
			t.Fatalf("write token: %v", err)
		}

		got, err := readSelfSubject(path)
		if err != nil {
			t.Fatalf("readSelfSubject() error: %v", err)
		}
		if got != "system:serviceaccount:ns:sa" {
			t.Errorf("got %q, want %q", got, "system:serviceaccount:ns:sa")
		}
	})

	t.Run("missing file returns error", func(t *testing.T) {
		_, err := readSelfSubject("/no/such/path/token")
		if err == nil {
			t.Fatal("expected error for missing file, got nil")
		}
	})
}
