# Stage 1: Generate BPF objects and build Go binary
FROM golang:1.25-bookworm AS builder

# Install BPF build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy go module files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Generate BPF Go bindings (no vmlinux.h needed — uses inline CO-RE structs)
RUN cd pkg/ebpf && go generate

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o conntrack-ebpf-exporter ./cmd/

# Stage 2: Minimal runtime image
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/conntrack-ebpf-exporter /conntrack-ebpf-exporter

ENTRYPOINT ["/conntrack-ebpf-exporter"]
