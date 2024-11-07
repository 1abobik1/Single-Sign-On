package app

import (
	"log/slog"
	"time"

	grpcapp "github.com/1abobik1/Single-Sign-On/internal/app/grpc"
	"github.com/1abobik1/Single-Sign-On/internal/services/auth"
	"github.com/1abobik1/Single-Sign-On/internal/storage/postgresql"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, storagePath string, AcessTokenTTL time.Duration, RefreshTokenTTL time.Duration) *App {
	storage, err := postgresql.New(storagePath)
	if err != nil {
		panic(err)
	}
	authservice := auth.New(log, storage, AcessTokenTTL, RefreshTokenTTL)
	grpcApp := grpcapp.New(log, authservice, grpcPort)

	return &App{
		GRPCSrv: grpcApp,
	}
}
