package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/1abobik1/Single-Sign-On/internal/domain/models"
	jwt "github.com/1abobik1/Single-Sign-On/internal/lib/jwt"
	"github.com/1abobik1/Single-Sign-On/internal/storage"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (user_id int64, err error)
	SaveRefreshToken(ctx context.Context, userID int64, refreshToken string) (err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}

type Auth struct {
	usrSaver        UserSaver
	usrProvider     UserProvider
	appProvider     AppProvider
	log             *slog.Logger
	AcessTokenTTL   time.Duration
	RefreshTokenTTL time.Duration
}

type Storage interface {
	UserSaver
	UserProvider
	AppProvider
}

func New(
	log *slog.Logger,
	storage Storage,
	AcessTokenTTL time.Duration,
	RefreshTokenTTL time.Duration,
) *Auth {
	return &Auth{
		usrSaver:        storage,
		usrProvider:     storage,
		appProvider:     storage,
		log:             log,
		AcessTokenTTL:   AcessTokenTTL,
		RefreshTokenTTL: RefreshTokenTTL,
	}
}

func (a *Auth) Login(ctx context.Context, email string, password string, appID int) (string, string, error) {
	const op = "Auth.Login"

	a.log.With(
		"op", op,
		"email", email,
	).Info("attempting to log in user")

	// Проверка наличия пользователя
	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found")
			return "", "", storage.ErrUserNotFound
		}
		a.log.Error("failed to retrieve user", "error", err)
		return "", "", fmt.Errorf("%s: %v", op, err)
	}

	// Проверка пароля
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Warn("invalid password")
		return "", "", ErrInvalidCredentials
	}

	// Получение информации о приложении
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("app not found", "error", err)
			return "", "", storage.ErrAppNotFound
		}
		a.log.Error("failed to retrieve app", "error", err)
		return "", "", fmt.Errorf("%s: %v", op, err)
	}

	// Генерация нового access токена
	accessToken, err := jwt.NewAccessToken(user, app, a.AcessTokenTTL)
	if err != nil {
		a.log.Error("failed to generate JWT", "error", err)
		return "", "", fmt.Errorf("%s: %v", op, err)
	}

	// Проверка существования refresh токена
	refreshToken := user.RefreshToken
	if refreshToken == "" {
		// Если токен отсутствует, создаем новый refresh токен
		refreshToken, err = jwt.NewRefreshToken(user, app, 30*24*time.Hour) // Установите срок жизни refresh токена, например, 30 дней
		if err != nil {
			a.log.Error("failed to generate refresh token", "error", err)
			return "", "", fmt.Errorf("%s: %v", op, err)
		}
		// Сохраняем refresh токен в базе данных
		if err := a.usrSaver.SaveRefreshToken(ctx, user.ID, refreshToken); err != nil {
			a.log.Error("failed to save refresh token", "error", err)
			return "", "", fmt.Errorf("%s: %v", op, err)
		}
	}

	a.log.Info("user logged in successfully")
	return accessToken, refreshToken, nil
}

func (a *Auth) RegisterNewUser(ctx context.Context, email string, pass string, appID int) (string, string, error) {
	const op = "auth.RegisterNewUser"

	// Логирование регистрации
	a.log.With("op", op, "email", email).Info("attempting to register user")

	// Хешируем пароль
	passHash, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	if err != nil {
		a.log.Error("failed to generate password hash", "error", err)
		return "", "", fmt.Errorf("%s: %v", op, err)
	}

	// Сохраняем пользователя в БД
	userID, err := a.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			a.log.Warn("user already exists", "error", err)
			return "", "", fmt.Errorf("user with this email already exists")
		}
		a.log.Error("failed to save user", "error", err)
		return "", "", fmt.Errorf("%s: %v", op, err)
	}

	// Получаем пользователя и приложение для токенов
	user := models.User{ID: userID, Email: email, PassHash: passHash}
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", "", fmt.Errorf("%s: %v", op, err)
	}

	accessToken, err := jwt.NewAccessToken(user, app, a.AcessTokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("%s: %v", op, err)
	}

	refreshToken, err := jwt.NewRefreshToken(user, app, a.RefreshTokenTTL)
	if err != nil {
		return "", "", fmt.Errorf("%s: %v", op, err)
	}

	// Сохраняем refresh токен в БД (чтобы можно было использовать его для обновления)
	if err := a.usrSaver.SaveRefreshToken(ctx, userID, refreshToken); err != nil {
		return "", "", fmt.Errorf("%s: %v", op, err)
	}

	a.log.Info("user registered and tokens generated successfully")
	return accessToken, refreshToken, nil
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

func (a *Auth) RefreshAccessToken(ctx context.Context, refreshToken string, appID int) (string, error) {
	const op = "Auth.RefreshAccessToken"

	// Проверка refresh токена
	claims, err := jwt.ParseRefreshToken(refreshToken, a.appProvider, appID)
	if err != nil {
		a.log.Warn("invalid refresh token")
		return "", ErrInvalidCredentials
	}

	// Получение информации о пользователе по UID
	userID, ok := claims["uid"].(int64)
	if !ok {
		return "", ErrInvalidCredentials
	}

	user, err := a.usrProvider.UserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found")
			return "", storage.ErrUserNotFound
		}
		a.log.Error("failed to retrieve user", "error", err)
		return "", fmt.Errorf("%s: %v", op, err)
	}

	// Проверка appID
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			a.log.Warn("app not found", "error", err)
			return "", storage.ErrAppNotFound
		}
		a.log.Error("failed to retrieve app", "error", err)
		return "", fmt.Errorf("%s: %v", op, err)
	}

	// Генерация нового access токена
	accessToken, err := jwt.NewAccessToken(user, app, a.AcessTokenTTL)
	if err != nil {
		a.log.Error("failed to generate JWT", "error", err)
		return "", fmt.Errorf("%s: %v", op, err)
	}

	a.log.Info("access token refreshed successfully")
	return accessToken, nil
}
