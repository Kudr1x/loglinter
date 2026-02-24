lint:
	go fix ./...
	golangci-lint run ./...
	@echo "ok"

test:
	go test ./pkg/analyzer/...

build:
	go build -buildmode=plugin -o loglinter.so ./plugin/main.go