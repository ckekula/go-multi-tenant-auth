package handlers

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	proto "go-multi-tenant-auth/internal/handlers/proto"
	"go-multi-tenant-auth/internal/tenant"

	"github.com/zitadel/zitadel-go/v3/pkg/authorization"
	"github.com/zitadel/zitadel-go/v3/pkg/authorization/oauth"
	"github.com/zitadel/zitadel-go/v3/pkg/grpc/middleware"
)

var _ proto.AuthServiceServer = (*Server)(nil)

var (
	// This list allows to specify the authorization checks required to call the corresponding endpoint.
	// If an endpoint (e.g. [proto.AuthService_Healthz_FullMethodName]) is not added to the list, it will be publicly accessible.
	// By adding specific [authorization.CheckOption], additional requirements like role checks ([authorization.WithRole]) can be defined.
	Checks = map[string][]authorization.CheckOption{
		proto.AuthService_Healthz_FullMethodName:   nil,
		proto.AuthService_AddTask_FullMethodName:   {authorization.WithRole("admin")},
		proto.AuthService_AddTasks_FullMethodName:  {authorization.WithRole("admin")},
		proto.AuthService_ListTasks_FullMethodName: nil, // requires valid token, no role
	}
)

type Server struct {
	proto.UnimplementedAuthServiceServer

	mw *middleware.Interceptor[*oauth.IntrospectionContext]
	mu sync.RWMutex
	// tasks are used to store an in-memory list used in the protected endpoint
	tasks map[string][]string // orgID -> tasks
}

func NewServer(mw *middleware.Interceptor[*oauth.IntrospectionContext]) *Server {
	return &Server{mw: mw, tasks: make(map[string][]string)}
}

// Healthz is accessible by anyone and will always return "OK" to indicate the API is running
func (s *Server) Healthz(_ context.Context, _ *proto.HealthzRequest) (*proto.HealthzResponse, error) {
	return &proto.HealthzResponse{
		Health: "OK",
	}, nil
}

// ListTasks is only accessible with a valid authorization (in this case a valid access_token / PAT).
// It will list all stored tasks. In case the user is granted the `admin` role it will add a separate task telling him
// to add a new task.
func (s *Server) ListTasks(ctx context.Context, _ *proto.ListTasksRequest) (*proto.ListTasksResponse, error) {
	// Scope tasks by orgID
	orgID := tenant.OrgIDFromCtx(ctx)
	s.mu.RLock()
	taskList := append([]string{}, s.tasks[orgID]...)
	s.mu.RUnlock()

	// Using the [middleware.Context] function we can gather information about the authorized user.
	// This example will just print the users ID using the provided method, and it will also
	// print the username by directly access the field of the typed [*oauth.IntrospectionContext].
	authCtx := s.mw.Context(ctx)
	slog.Info("user accessed task list", "id", authCtx.UserID(), "username", authCtx.Username)

	// Although this endpoint is accessible by any authorized user, you might want to take additional steps
	// if the user is granted a specific role. In this case an `admin` will be informed to add a new task:
	if authCtx.IsGrantedRole("admin") {
		taskList = append(taskList, "create a new task with `AddTask`")
	}

	return &proto.ListTasksResponse{Tasks: taskList}, nil
}

// AddTask is only accessible with a valid authorization, which was granted the `admin` role (in any organization).
// It will add the provided task to the list of existing ones.
func (s *Server) AddTask(ctx context.Context, req *proto.AddTaskRequest) (*proto.AddTaskResponse, error) {
	// get the provided task and do not accept an empty value
	if req.GetTask() == "" {
		return nil, status.Error(codes.InvalidArgument, "task must not be empty")
	}

	// Scope tasks by orgID
	orgID := tenant.OrgIDFromCtx(ctx)
	s.mu.Lock()
	s.tasks[orgID] = append(s.tasks[orgID], req.GetTask())
	s.mu.Unlock()

	// since we only want the authorized userID and don't need any specific data, we can simply use [authorization.UserID]
	slog.Info("admin added task", "id", authorization.UserID(ctx), "task", req.GetTask())

	// inform the admin about the successful addition
	return &proto.AddTaskResponse{
		Added: fmt.Sprintf("task `%s` added", req.GetTask()),
	}, nil
}

// AddTasks is only accessible with a valid authorization, which was granted the `admin` role (in any organization).
// It demonstrates that GRPC client Stream can be used the same way a standard RPC methods.
// It will also add the provided task(s) to the list of existing ones.
func (s *Server) AddTasks(stream proto.AuthService_AddTasksServer) error {
	var count uint32
	orgID := tenant.OrgIDFromCtx(stream.Context())
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			// the client stream ended, so let's check the list
			if count == 0 {
				return status.Error(codes.InvalidArgument, "no task provided")
			}

			// return the amount of successfully added task to the client
			return stream.SendAndClose(&proto.AddTasksResponse{Added: count})
		}
		if err != nil {
			return err
		}

		// If there was no error, let's check if the task was not empty and then directly add it to the list.
		// We'll also log it again and count up the amount.
		if req.GetTask() != "" {
			s.mu.Lock()
			s.tasks[orgID] = append(s.tasks[orgID], req.GetTask())
			s.mu.Unlock()
			slog.Info("admin added task", "id", authorization.UserID(stream.Context()), "task", req.GetTask())
			count++
		}
	}
}
