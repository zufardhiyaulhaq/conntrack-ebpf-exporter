# Stage 1: Build Go binary
FROM golang:1.25-bookworm AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o conntrack-ebpf-exporter ./cmd/

# Stage 2: Runtime image with BPF compilation tools
# BPF program is compiled at startup against the running kernel's vmlinux.h
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/conntrack-ebpf-exporter /conntrack-ebpf-exporter
COPY bpf/ /bpf/

ENTRYPOINT ["/conntrack-ebpf-exporter"]
