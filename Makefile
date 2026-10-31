COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X github.com/k4ran909/whalescale/internal/version.Commit=$(COMMIT)

.PHONY: build test generate lint clean web docker

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...

test:
	go test -timeout 5m ./...

generate:
	buf lint
	buf generate

lint:
	go vet ./...

clean:
	rm -rf bin dist

web:
	cd web && npm ci --no-audit --no-fund && npm run build

docker:
	docker build -t whalescale:dev --build-arg COMMIT=$(COMMIT) .
