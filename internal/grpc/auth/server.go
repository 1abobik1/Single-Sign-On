package auth

import (
	"context"

	sso "github.com/1abobik1/ProtoBuf/gen/go/sso"
	"google.golang.org/grpc"
)

type serverAPI struct {
	sso.UnimplementedAuthServer
}

func RegisterServerAPI(gRPC *grpc.Server) {
	sso.RegisterAuthServer(gRPC, &serverAPI{})
}

func (s *serverAPI) Login(ctx context.Context, req *sso.LoginRequest) (*sso.LoginResponse, error) {
	panic("zapolni meni")
}

func (s *serverAPI) Register(ctx context.Context, reg *sso.RegisterRequest) (*sso.RegisterResponse, error) {
	panic("zapolni meni")
}

func (s *serverAPI) IsAdmin(ctx context.Context, admin *sso.IsAdminRequest) (*sso.IsAdminReponse, error) {
	panic("implement me")
}
