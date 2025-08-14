# Focus on core functionality only
.PHONY: build test clean run lint fmt help

build:
	go build -ldflags "-X main.Version=$(VERSION)" -o cert-monitor .

test:
	go test -race ./...

clean:
	rm -f cert-monitor coverage*.out

run:
	./cert-monitor -config config.yaml

lint:
	golangci-lint run

fmt:
	go fmt ./...
