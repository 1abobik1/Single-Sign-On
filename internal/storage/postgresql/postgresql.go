package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/1abobik1/Single-Sign-On/internal/domain/models"
	"github.com/1abobik1/Single-Sign-On/internal/storage"
	"github.com/lib/pq" // Регистрация драйвера PostgreSQL
)

type Storage struct {
	db *sql.DB
}

// New создает новое подключение к базе данных PostgreSQL.
func New(storagePath string) (*Storage, error) {
	const op = "storage.postresql.New"

	db, err := sql.Open("postgres", storagePath)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", op, err)
	}

	return &Storage{db: db}, nil
}

// Stop закрывает подключение к базе данных.
func (s *Storage) Stop() error {
	return s.db.Close()
}

// SaveUser добавляет пользователя в таблицу users и возвращает его ID.
func (s *Storage) SaveUser(ctx context.Context, email string, passHash []byte) (int64, error) {
	const op = "storage.postgresql.SaveUser"

	var id int64
	err := s.db.QueryRowContext(ctx, "INSERT INTO users(email, pass_hash) VALUES($1, $2) RETURNING id", email, passHash).Scan(&id)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" { // 23505 - уникальное ограничение
			return 0, fmt.Errorf("%s: %v", op, storage.ErrUserExists)
		}
		return 0, fmt.Errorf("%s: %v", op, err)
	}

	return id, nil
}

// User ищет пользователя по email.
func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgresql.User"

	var user models.User
	err := s.db.QueryRowContext(ctx, "SELECT id, email, pass_hash FROM users WHERE email = $1", email).
		Scan(&user.ID, &user.Email, &user.PassHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.User{}, fmt.Errorf("%s: %v", op, storage.ErrUserNotFound)
		}
		return models.User{}, fmt.Errorf("%s: %v", op, err)
	}

	return user, nil
}

// App ищет приложение по ID.
func (s *Storage) App(ctx context.Context, id int) (models.App, error) {
	const op = "storage.postgresql.App"

	var app models.App
	err := s.db.QueryRowContext(ctx, "SELECT id, name, secret FROM apps WHERE id = $1", id).
		Scan(&app.ID, &app.Name, &app.Secret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.App{}, fmt.Errorf("%s: %v", op, storage.ErrAppNotFound)
		}
		return models.App{}, fmt.Errorf("%s: %v", op, err)
	}

	return app, nil
}

// IsAdmin проверяет, является ли пользователь администратором.
func (s *Storage) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "storage.postgresql.IsAdmin"

	var isAdmin bool
	err := s.db.QueryRowContext(ctx, "SELECT is_admin FROM users WHERE id = $1", userID).Scan(&isAdmin)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, fmt.Errorf("%s: %v", op, storage.ErrUserNotFound)
		}
		return false, fmt.Errorf("%s: %v", op, err)
	}

	return isAdmin, nil
}
