.PHONY: all static-linux static-freebsd clean default

# Detect local platform
GOOS   := $(shell go env GOOS)
GOARCH := $(shell go env GOARCH)
BINARY := vuxml-go-$(GOOS)-$(GOARCH)

# Default: static build for local platform/arch
default: $(BINARY)

$(BINARY): main.go
	CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o $(BINARY) main.go

# All 4 static builds
all: static-linux static-freebsd

static-linux:
	GOOS=linux   GOARCH=amd64  CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o vuxml-go-linux-amd64  main.go
	GOOS=linux   GOARCH=arm64  CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o vuxml-go-linux-arm64  main.go

static-freebsd:
	GOOS=freebsd GOARCH=amd64  CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o vuxml-go-freebsd-amd64  main.go
	GOOS=freebsd GOARCH=arm64  CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o vuxml-go-freebsd-arm64  main.go

clean:
	rm -f vuxml-go-* vuxml-go

