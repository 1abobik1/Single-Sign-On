package jwt

import (
	"time"

	"github.com/1abobik1/Single-Sign-On/internal/domain/models"

	"github.com/golang-jwt/jwt/v5"
)

func NewAccessToken(user models.User, app models.App, duration time.Duration) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix()
	claims["app_id"] = app.ID

	tokenString, err := token.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func NewRefreshToken(user models.User, app models.App, duration time.Duration) (string, error) {
	refreshToken := jwt.New(jwt.SigningMethodHS256)

	claims := refreshToken.Claims.(jwt.MapClaims)
	claims["uid"] = user.ID
	claims["email"] = user.Email
	claims["exp"] = time.Now().Add(duration).Unix() // e.g., 25 days expiration for refresh token 25 * 24 * time.Hour
	claims["app_id"] = app.ID

	refreshTokenString, err := refreshToken.SignedString([]byte(app.Secret))
	if err != nil {
		return "", err
	}

	return refreshTokenString, nil
}
