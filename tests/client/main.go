package main

import (
	"context"
	"fmt"
	"time"

	sso "github.com/1abobik1/ProtoBuf/gen/go/sso"
	grpc_logging "github.com/grpc-ecosystem/go-grpc-middleware/logging/logrus"
	grpcretry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	"github.com/sirupsen/logrus"
	"github.com/thanhpk/randstr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	api sso.AuthClient
	log *logrus.Entry
}

func New(ctx context.Context, log *logrus.Entry, addr string, timeout time.Duration, retriesCount int) (*Client, error) {
	const op = "client.New"
	retryOpts := []grpcretry.CallOption{
		grpcretry.WithCodes(codes.NotFound, codes.Aborted, codes.DeadlineExceeded),
		grpcretry.WithMax(uint(retriesCount)),
		grpcretry.WithPerRetryTimeout(timeout),
	}

	// Используем middleware для логирования вместо grpclog
	grpc_logging.ReplaceGrpcLogger(log)
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(grpcretry.UnaryClientInterceptor(retryOpts...)),
		grpc.WithUnaryInterceptor(grpc_logging.UnaryClientInterceptor(log)),
	}

	cc, err := grpc.DialContext(ctx, addr, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("%s %v", op, err)
	}

	client := &Client{
		api: sso.NewAuthClient(cc),
		log: log,
	}
	return client, nil
}

func (c *Client) RegisterUser(ctx context.Context, email, password string) {
	response, err := c.api.Register(ctx, &sso.RegisterRequest{
		Email:    email,
		Password: password,
	})
	if err != nil {
		c.log.Errorf("Failed to register user: %v", err)
		return
	}
	c.log.Infof("Registered user with ID: %d", response.UserId)
}

func (c *Client) LoginUser(ctx context.Context, email, password string, appId int32) {
	response, err := c.api.Login(ctx, &sso.LoginRequest{
		Email:    email,
		Password: password,
		AppId:    appId,
	})
	if err != nil {
		c.log.Errorf("Failed to login user: %v", err)
		return
	}
	c.log.Infof("User logged in with token: %s", response.Token)
}

func (c *Client) CheckAdminStatus(ctx context.Context, userID int64) {
	response, err := c.api.IsAdmin(ctx, &sso.IsAdminRequest{
		UserId: userID,
	})
	if err != nil {
		c.log.Errorf("Failed to check admin status: %v", err)
		return
	}
	c.log.Infof("User admin status: %v", response.IsAdmin)
}

func (c *Client) GetUSerID(ctx context.Context, email string, password string) int64 {
	registerResponse, err := c.api.Register(ctx, &sso.RegisterRequest{Email: email, Password: password})
	if err != nil {
		c.log.Fatalf("Failed to register user: %v", err)
	}

	return registerResponse.UserId
}

func main() {
	// Create client
	log := logrus.NewEntry(logrus.New())
	ctx := context.Background()
	client, err := New(ctx, log, "localhost:44044", time.Second*5, 3)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// check 5 req
	for i := 0; i < 5; i++ {
		regEmail := randstr.Hex(8)
		regPswd := randstr.Hex(8)
		client.RegisterUser(ctx, regEmail, regPswd)
		client.LoginUser(ctx, regEmail, regPswd, 1)

		checkAdminemai := randstr.Hex(8)
		checkAdminpswd := randstr.Hex(8)
		userID := client.GetUSerID(ctx, checkAdminemai, checkAdminpswd)
		client.CheckAdminStatus(ctx, userID)
	}
}
