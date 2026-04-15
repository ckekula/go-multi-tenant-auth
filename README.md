# Identity Service

Minimal multi-tenant auth microservice backed by [Zitadel](https://zitadel.com).  
Tokens are validated **locally** via JWKS — no round-trip to Zitadel per request.

## Architecture

```
Client
  │
  │  Authorization: Bearer <access_token>
  ▼
identity-service
  ├── GET /healthz          — liveness (no auth)
  ├── GET /api/me           — caller identity
  └── GET /api/tenant       — tenant / org claims
        │
        │  validate JWT against Zitadel JWKS (fetched at startup)
        ▼
  TenantClaims{OrgID, OrgName, ProjectRoles, …}
```

## Prerequisites

1. A Zitadel instance (cloud or self-hosted).
2. A **Project** with at least one **Application** (type: *User Agent* or *Native*).
3. Note the **Client ID** and **Discovery Endpoint** from the application settings.
4. For multi-tenancy, ensure **"Assert Roles on Authentication"** is enabled in the
   project settings so `urn:zitadel:iam:org:project:roles` is included in the token.

## Configuration

| Env var | Example | Description |
|---|---|---|
| `ZITADEL_DOMAIN` | `https://acme.zitadel.cloud` | Your instance URL (no trailing slash) |
| `ZITADEL_CLIENT_ID` | `123456789@project` | Client ID from your Zitadel app |
| `PORT` | `8080` | HTTP port (default: 8080) |

## Run

```bash
go mod tidy

ZITADEL_DOMAIN=https://your-instance.zitadel.cloud \
ZITADEL_CLIENT_ID=your-client-id \
go run ./cmd/main.go
```

## Usage

Obtain an access token from Zitadel (e.g. via PKCE flow or device code), then:

```bash
# Health check (no token needed)
curl http://localhost:8080/healthz

# Identity of the caller
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/me

# Tenant information
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/tenant
```

### Example `/api/tenant` response

```json
{
  "org_id": "252343545657678",
  "org_name": "acme-corp",
  "roles": {
    "admin": { "252343545657678": "acme-corp.zitadel.cloud" }
  }
}
```

## Multi-tenancy model

Each Zitadel **Organization** maps to one tenant. The JWT carries:

| Claim | Meaning |
|---|---|
| `urn:zitadel:iam:org:id` | Unique org/tenant ID |
| `urn:zitadel:iam:org:name` | Human-readable org name |
| `urn:zitadel:iam:org:project:roles` | Role → org → domain map |

Downstream services extract `org_id` from the validated `TenantClaims` to scope
database queries, feature flags, and billing to the correct tenant.

## Production considerations

- **JWKS refresh**: `loadKeyFunc` is called once at startup. In production, refresh
  keys in a background goroutine (e.g. every 1 h) to handle key rotation.
- **Token introspection**: For opaque tokens or stricter revocation guarantees,
  replace local JWT validation with Zitadel's `/oauth/v2/introspect` endpoint.
- **TLS**: Terminate TLS at your load balancer or add `srv.ListenAndServeTLS`.
- **Metrics**: Wrap handlers with a Prometheus middleware for latency and error rate.