package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Config holds all runtime configuration.
type Config struct {
	ZitadelDomain string // e.g. https://your-instance.zitadel.cloud
	ClientID      string
	Port          string
}

// TenantClaims represents the validated JWT payload, extended with
// Zitadel-specific multi-tenant fields.
type TenantClaims struct {
	jwt.RegisteredClaims

	// Standard OIDC
	Email string `json:"email"`
	Name  string `json:"name"`

	// Zitadel organisation / tenant identifiers
	OrgID   string `json:"urn:zitadel:iam:org:id"`
	OrgName string `json:"urn:zitadel:iam:org:name"`

	// Project roles — map[roleKey]map[orgID]orgDomain
	ProjectRoles map[string]map[string]string `json:"urn:zitadel:iam:org:project:roles"`
}

// AuthService validates JWTs and extracts tenant information.
type AuthService struct {
	cfg        Config
	logger     *slog.Logger
	httpClient *http.Client

	mu      sync.RWMutex
	keyFunc jwt.Keyfunc
}

// oidcDiscovery is the minimal subset we need from /.well-known/openid-configuration.
type oidcDiscovery struct {
	JWKSURI string `json:"jwks_uri"`
	Issuer  string `json:"issuer"`
}

// jwksResponse is the raw JWKS payload.
type jwksResponse struct {
	Keys []json.RawMessage `json:"keys"`
}

type KeySet struct {
	Keys map[string]interface{}
}

// NewAuthService fetches the OIDC discovery document, resolves the JWKS URI,
// and wires up token validation. Call once at startup.
func NewAuthService(ctx context.Context, cfg Config, logger *slog.Logger) (*AuthService, error) {
	svc := &AuthService{
		cfg:    cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	if err := svc.loadKeyFunc(ctx); err != nil {
		return nil, err
	}

	return svc, nil
}

// loadKeyFunc hits the OIDC discovery endpoint and builds a jwt.Keyfunc
// backed by the JWKS. In production, wrap this in a background goroutine
// that refreshes keys periodically.
func (s *AuthService) loadKeyFunc(ctx context.Context) error {
	discoveryURL := s.cfg.ZitadelDomain + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return fmt.Errorf("build discovery request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("discovery endpoint returned %d", resp.StatusCode)
	}

	var doc oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("decode discovery document: %w", err)
	}

	s.logger.Info("discovered OIDC metadata", "issuer", doc.Issuer, "jwks_uri", doc.JWKSURI)

	// Build a JWKS-backed key function using the standard jwt library helper.
	// jwt.NewCachingJWKSProvider is available in golang-jwt/jwt v5 via the
	// jwks package; here we fetch once and build a static map for clarity.
	keys, err := s.fetchJWKS(ctx, doc.JWKSURI)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}

	issuer := doc.Issuer

	s.mu.Lock()
	s.keyFunc = buildKeyFunc(keys, issuer, s.cfg.ClientID)
	s.mu.Unlock()

	return nil
}

// fetchJWKS downloads the JWKS and parses it into a keyset.
func (s *AuthService) fetchJWKS(ctx context.Context, uri string) (*KeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// We rely on golang-jwt's ParseWithClaims which accepts a Keyfunc.
	// The JWKS is parsed via jwt.ParseRSAPublicKeyFromPEM / ECDSA equivalents.
	// To avoid a heavy JWKS library we store the raw JSON and parse per-kid.
	var raw jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}

	keyset := &KeySet{Keys: make(map[string]interface{})}
	for _, keyJSON := range raw.Keys {
		key, kid, err := parseJWK(keyJSON)
		if err != nil {
			s.logger.Warn("skipping unparseable JWK", "error", err)
			continue
		}
		keyset.Keys[kid] = key
	}

	s.logger.Info("loaded JWKs", "count", len(keyset.Keys))
	return keyset, nil
}

// ValidateToken parses and validates a raw JWT string.
// Returns the structured TenantClaims on success.
func (s *AuthService) ValidateToken(tokenStr string) (*TenantClaims, error) {
	s.mu.RLock()
	kf := s.keyFunc
	s.mu.RUnlock()

	claims := &TenantClaims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, kf,
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return claims, nil
}

// buildKeyFunc returns a jwt.Keyfunc that looks up the signing key by kid
// and validates issuer + audience.
func buildKeyFunc(ks *KeySet, issuer, clientID string) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		// Enforce algorithm family (RS256/ES256 only — never "none").
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
			// allowed
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid header")
		}

		key, found := ks.Keys[kid]
		if !found {
			return nil, fmt.Errorf("unknown kid: %s", kid)
		}

		// Validate issuer.
		iss, err := t.Claims.GetIssuer()
		if err != nil || iss != issuer {
			return nil, fmt.Errorf("issuer mismatch: got %q want %q", iss, issuer)
		}

		// Validate audience contains our client ID.
		aud, err := t.Claims.GetAudience()
		if err != nil {
			return nil, fmt.Errorf("missing audience: %w", err)
		}
		found = false
		for _, a := range aud {
			if a == clientID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("audience mismatch: client_id %q not in token", clientID)
		}

		return key, nil
	}
}
