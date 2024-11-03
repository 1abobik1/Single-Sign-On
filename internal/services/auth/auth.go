package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/1abobik1/Single-Sign-On/internal/domain/models"
	"github.com/1abobik1/Single-Sign-On/internal/lib/jwt"
	"github.com/1abobik1/Single-Sign-On/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (user_id int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

type Auth struct {
	usrSaver    UserSaver
	usrProvider UserProvider
	appProvider AppProvider
	log         *slog.Logger
	tokenTTL    time.Duration
}

type Storage interface {
	UserSaver
	UserProvider
	AppProvider
}

func New(
	log *slog.Logger,
	storage Storage,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		usrSaver:    storage,
		usrProvider: storage,
		appProvider: storage,
		log:         log,
		tokenTTL:    tokenTTL,
	}
}

func (a *Auth) Login(ctx context.Context, email string, password string, appID int) (string, error) {
	const op = "Auth.Login"

	a.log.With(
		"op", op,
		"email", email,
	).Info("attempting to log in user")

	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found")
			return "", storage.ErrUserNotFound
		}
		a.log.Error("failed to retrieve user", "error", err)
		return "", fmt.Errorf("%s: %v", op, err)
	}

	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Warn("invalid password")
		return "", ErrInvalidCredentials
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("app not found", "error", err)
			return "", storage.ErrAppNotFound
		}
		a.log.Error("failed to retrieve app", "error", err)
		return "", fmt.Errorf("%s: %v", op, err)
	}

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate JWT", "error", err)
		return "", fmt.Errorf("%s: %v", op, err)
	}

	a.log.Info("user logged in successfully")
	return token, nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, email string, pass string) (int64, error) {
	const op = "auth.RegisterNewUser"

	a.log.With(
		"op", op,
		"email", email,
	).Info("attempting to register user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		a.log.Error("failed to generate password hash", "error", err)
		return 0, fmt.Errorf("%s: %v", op, err)
	}

	id, err := a.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			a.log.Warn("user already exists", "error", err)
			return 0, fmt.Errorf("user with this email already exists")
		}
		a.log.Error("failed to save user", "error", err)
		return 0, fmt.Errorf("%s: %v", op, err)
	}

	a.log.Info("user registered successfully")
	return id, nil
}

func (a *Auth) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "Auth.IsAdmin"

	a.log.With(
		"op", op,
		"userID", userID,
	).Info("checking if user is admin")

	isAdmin, err := a.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found for admin check", "error", err)
			return false, storage.ErrUserNotFound
		}
		a.log.Error("failed to check admin status", "error", err)
		return false, fmt.Errorf("%s: %v", op, err)
	}

	a.log.Info("checked admin status", "isAdmin", isAdmin)
	return isAdmin, nil
}
