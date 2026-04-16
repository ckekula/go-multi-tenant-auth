package tenant

import (
	"context"
	"fmt"
	"sync"
)

type Registry struct {
	mu    sync.RWMutex
	store map[string]string // tenantID -> zitadel orgID
}

func NewRegistry(initial map[string]string) *Registry {
	return &Registry{store: initial}
}

func (r *Registry) OrgID(ctx context.Context, tenantID string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	orgID, ok := r.store[tenantID]
	if !ok {
		return "", fmt.Errorf("unknown tenant: %s", tenantID)
	}
	return orgID, nil
}
