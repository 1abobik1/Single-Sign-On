package main

import (
	"fmt"

	"github.com/1abobik1/Single-Sign-On/internal/config"
)

func main() {
	cfg := config.MustLoad() // go run cmd/sso/main.go --config=./config/local.yaml   для локального запуска(в продакшене использовать другой)

	fmt.Println(cfg)
}
