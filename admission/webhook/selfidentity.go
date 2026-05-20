package webhook

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// defaultServiceAccountTokenPath is the path at which the projected service
// account token is mounted inside the pod.
const defaultServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// readSelfSubject returns the operator's own admission subject (the value that
// will appear as UserInfo.Name on admission requests originating from this
// pod) by parsing the unverified `sub` claim out of the projected service
// account token at tokenPath.
//
// Returns ("", err) if the token cannot be read or parsed. Callers should
// treat an error as "self-detection unavailable" and continue without the
// short-circuit rather than failing startup.
func readSelfSubject(tokenPath string) (string, error) {
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("read service account token: %w", err)
	}
	token := strings.TrimSpace(string(data))
	return subjectFromJWT(token)
}

// subjectFromJWT extracts the `sub` claim from a JWT without verifying the
// signature. The token is only used to identify our own pod, so the signature
// is irrelevant — if an attacker can replace the projected token volume they
// already have full control of the operator's identity.
func subjectFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT: expected 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("parse JWT claims: %w", err)
	}
	if claims.Sub == "" {
		return "", fmt.Errorf("JWT has empty sub claim")
	}
	return claims.Sub, nil
}
