.PHONY: all static-linux static-freebsd clean

all:
	CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o vuxml-go main.go

static-linux:
	GOOS=linux   GOARCH=amd64  CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o vuxml-go-linux-amd64  main.go
	GOOS=linux   GOARCH=arm64  CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o vuxml-go-linux-arm64  main.go

static-freebsd:
	GOOS=freebsd GOARCH=amd64  CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o vuxml-go-freebsd-amd64  main.go
	GOOS=freebsd GOARCH=arm64  CGO_ENABLED=0 go build -ldflags="-s -w -extldflags '-static'" -o vuxml-go-freebsd-arm64  main.go

clean:
	rm -f vuxml-go-* vuxml-go

