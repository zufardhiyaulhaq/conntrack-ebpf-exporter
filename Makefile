BINARY_NAME := conntrack-ebpf-exporter
IMAGE_NAME := conntrack-ebpf-exporter
IMAGE_TAG := latest

.PHONY: all generate build docker clean test lint

all: generate build

## generate: Generate BPF Go bindings (Linux only, requires clang)
generate:
	@echo "==> Generating BPF Go bindings..."
	cd pkg/ebpf && go generate

## build: Build the Go binary (Linux amd64)
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME) ./cmd/

## docker: Build the Docker image (generates BPF inside container)
docker:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

## clean: Remove build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f pkg/ebpf/conntrack_bpfel.go pkg/ebpf/conntrack_bpfel.o

## test: Run Go tests
test:
	go test ./pkg/...

## lint: Run linter
lint:
	golangci-lint run ./...
