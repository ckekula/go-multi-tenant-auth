package tenant

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const TenantHeader = "x-tenant-id"

type contextKey string

const (
	tenantIDKey contextKey = "tenantID"
	orgIDKey    contextKey = "orgID"
)

func TenantIDFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(tenantIDKey).(string)
	return v
}

func OrgIDFromCtx(ctx context.Context) string {
	v, _ := ctx.Value(orgIDKey).(string)
	return v
}

func NewUnaryInterceptor(reg *Registry) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, err := injectTenant(ctx, reg)
		if err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

func NewStreamInterceptor(reg *Registry) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := injectTenant(ss.Context(), reg)
		if err != nil {
			return err
		}
		return handler(srv, &wrappedStream{ss, ctx})
	}
}

func injectTenant(ctx context.Context, reg *Registry) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "missing metadata")
	}
	vals := md.Get(TenantHeader)
	if len(vals) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing x-tenant-id header")
	}
	tenantID := vals[0]
	orgID, err := reg.OrgID(ctx, tenantID)
	if err != nil {
		return nil, status.Error(codes.NotFound, err.Error())
	}
	ctx = context.WithValue(ctx, tenantIDKey, tenantID)
	ctx = context.WithValue(ctx, orgIDKey, orgID)
	return ctx, nil
}

type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context { return w.ctx }
