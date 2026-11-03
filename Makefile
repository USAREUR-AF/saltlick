BINARY := saltlick
PKG    := ./cmd/saltlick
DB     ?= saltlick.db
ADDR   ?= :8080

.PHONY: all build test vet fmt run clean image tidy check

all: check build

## build: single static binary, no cgo
build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) $(PKG)

## test: the whole suite
test:
	go test ./...

## vet: go vet
vet:
	go vet ./...

## fmt: refuse unformatted source
fmt:
	@out="$$(gofmt -l . )"; \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

## check: what CI runs
check: fmt vet test

## run: serve on $(ADDR) against $(DB)
run: build
	./$(BINARY) serve -addr $(ADDR) -db $(DB)

## image: container image
image:
	docker build -t saltlick:dev .

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) $(DB) $(DB)-wal $(DB)-shm
