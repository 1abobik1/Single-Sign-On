migrate:
	go run ./cmd/migrator/main.go --db-url="postgres://postgres:dima15042004@localhost:5432/SSO_DB?sslmode=disable" --migrations-path="./migrations"

migrate-down:
	go run ./cmd/migrator/main.go --db-url="postgres://postgres:dima15042004@localhost:5432/SSO_DB?sslmode=disable" --migrations-path="./migrations" -down

pg_dump:
	pg_dump -U postgres -h localhost -F c SSO_DB > ./storage/SSO_DB.dump

local-run:
	go run cmd/sso/main.go --config=./config/local.yaml

test:
	go run tests/client/main.go