.PHONY: all build clean client server test cert

all: build

build: client server

client:
	go build -o bin/client ./cmd/client

server:
	go build -o bin/server ./cmd/server

clean:
	rm -rf bin/

test:
	go test -v ./...

cert:
	@echo "Generating self-signed certificate..."
	openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"
	@echo "Certificate generated: server.crt, server.key"

run-client:
	./bin/client -config client_config.yaml

run-server:
	./bin/server -config server_config.yaml

