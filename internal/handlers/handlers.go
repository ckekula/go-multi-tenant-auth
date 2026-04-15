package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/ckekula/go-multi-tenant-auth/internal/services"
)

// Register wires all routes onto mux.
//
// Public routes:
//
//	GET  /healthz          — liveness probe
//
// Protected routes (require valid Zitadel JWT):
//
//	GET  /api/me           — returns claims for the authenticated user
//	GET  /api/tenant       — returns the tenant (org) extracted from the token
func Register(mux *http.ServeMux, svc *services.AuthService, logger *slog.Logger) {
	auth := AuthMiddleware(svc, logger)

	// Public
	mux.HandleFunc("GET /healthz", handleHealth)

	// Protected — wrap each handler individually so the middleware is applied
	// per-route. Swap to a router library (chi, gorilla/mux) if you need
	// route groups.
	mux.Handle("GET /api/me", auth(http.HandlerFunc(handleMe)))
	mux.Handle("GET /api/tenant", auth(http.HandlerFunc(handleTenant)))
}

// handleHealth is a simple liveness probe.
func handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleMe returns the identity of the authenticated caller.
func handleMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "claims not found in context")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"subject": claims.Subject,
		"email":   claims.Email,
		"name":    claims.Name,
		"org_id":  claims.OrgID,
		"roles":   claims.ProjectRoles,
	})
}

// handleTenant returns tenant (organisation) information for the caller.
// Useful as a gateway check: downstream services can call this to resolve
// the tenant before routing a request.
func handleTenant(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusInternalServerError, "claims not found in context")
		return
	}

	if claims.OrgID == "" {
		writeError(w, http.StatusForbidden, "token does not carry organisation claims")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"org_id":   claims.OrgID,
		"org_name": claims.OrgName,
		"roles":    claims.ProjectRoles,
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
