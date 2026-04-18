BINARY = yukvault
CGO_ENABLED = 1

build:
	CGO_ENABLED=1 go build -o $(BINARY) ./main.go

build-windows:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
	go build -o $(BINARY).exe ./main.go

test:
	go test ./internal/...

test-integration:
	go test -tags integration ./...

acceptance:
	bash ./scripts/acceptance-e2e.sh

install:
	go install ./...

lint:
	golangci-lint run ./...
