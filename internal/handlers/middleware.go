package handlers

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"go-multi-tenant-auth/internal/services"
)

// contextKey is an unexported type to avoid collisions in context values.
type contextKey string

const claimsKey contextKey = "tenant_claims"

// ClaimsFromContext retrieves the TenantClaims injected by the auth middleware.
func ClaimsFromContext(ctx context.Context) (*services.TenantClaims, bool) {
	c, ok := ctx.Value(claimsKey).(*services.TenantClaims)
	return c, ok
}

// AuthMiddleware validates the Bearer token on every request and injects
// the parsed TenantClaims into the request context.
func AuthMiddleware(svc *services.AuthService, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := extractBearer(r)
			if !ok {
				writeError(w, http.StatusUnauthorized, "missing or malformed Authorization header")
				return
			}

			claims, err := svc.ValidateToken(token)
			if err != nil {
				logger.Warn("token validation failed", "error", err, "remote", r.RemoteAddr)
				writeError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractBearer pulls the raw token from "Authorization: Bearer <token>".
func extractBearer(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", false
	}
	tok := strings.TrimPrefix(h, "Bearer ")
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", false
	}
	return tok, true
}
