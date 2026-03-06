BINARY_NAME := conntrack-ebpf-exporter
IMAGE_NAME := conntrack-ebpf-exporter
IMAGE_TAG := latest

.PHONY: all build docker clean test lint

all: build

## build: Build the Go binary (Linux amd64)
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd/

## docker: Build the Docker image
docker:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME)

## test: Run Go tests
test:
	go test ./pkg/...

## lint: Run linter
lint:
	golangci-lint run ./...

.PHONY: readme
readme:
	helm-docs -c ./charts/conntrack-ebpf-exporter -d > README.md
	helm-docs -c ./charts/conntrack-ebpf-exporter

.PHONY: helm.create.releases
helm.create.releases:
	helm package charts/conntrack-ebpf-exporter --destination charts/releases
	helm repo index charts/releases