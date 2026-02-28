//go:build linux

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	ebpfpkg "github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/ebpf"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/metrics"
	"github.com/zufardhiyaulhaq/conntrack-ebpf-exporter/pkg/resolver"
)

func main() {
	// Configure logging
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("Invalid log level %q: %v", logLevel, err)
	}
	log.SetLevel(level)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	// Read config
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Fatal("NODE_NAME environment variable is required (set via downward API)")
	}
	metricsPort := os.Getenv("METRICS_PORT")
	if metricsPort == "" {
		metricsPort = "9990"
	}

	metricBreakdown := strings.EqualFold(os.Getenv("METRIC_BREAKDOWN"), "true")

	cacheInterval := 30 * time.Second
	if v := os.Getenv("METRIC_CACHE_INTERVAL"); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("Invalid METRIC_CACHE_INTERVAL %q: %v", v, err)
		}
		cacheInterval = parsed
	}

	log.Infof("Starting conntrack-ebpf-exporter on node %s (metric breakdown: %v, cache interval: %s)", nodeName, metricBreakdown, cacheInterval)

	// Load kernel conntrack BPF program
	loader, err := ebpfpkg.NewLoader()
	if err != nil {
		log.Warnf("Kernel conntrack BPF loader failed (metrics will be empty): %v", err)
	} else {
		defer loader.Close()
	}

	// Open Cilium conntrack maps — prefer BPF iterator (kernel-side aggregation)
	// with fallback to userspace iteration.
	var ciliumReader ebpfpkg.CiliumReader
	iterReader, err := ebpfpkg.NewCiliumIterReader()
	if err != nil {
		log.Warnf("BPF iterator not available, falling back to userspace: %v", err)
		mapReader, err := ebpfpkg.NewCiliumReader()
		if err != nil {
			log.Warnf("Cilium CT reader not available (metrics will be empty): %v", err)
		} else {
			ciliumReader = mapReader
		}
	} else {
		ciliumReader = iterReader
	}
	if ciliumReader != nil {
		cachedReader, err := ebpfpkg.NewCachedCiliumReader(ciliumReader, cacheInterval)
		if err != nil {
			log.Warnf("Failed to initialize Cilium CT cache: %v", err)
		} else {
			ciliumReader = cachedReader
		}
		defer ciliumReader.Close()
	}

	// Create K8s client (in-cluster config)
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("Failed to get in-cluster config: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create K8s client: %v", err)
	}

	// Start pod resolver
	stopCh := make(chan struct{})
	podResolver := resolver.NewPodResolver(clientset, nodeName, stopCh)

	// Register node IP for node traffic attribution
	nodeIP := os.Getenv("NODE_IP")
	if nodeIP != "" {
		podResolver.SetNodeInfo(nodeIP, nodeName)
		log.Infof("Node IP %s registered for attribution", nodeIP)
	}

	// Register kernel conntrack collector
	if loader != nil {
		collector := metrics.NewCollector(loader, podResolver, metricBreakdown, nodeName)
		prometheus.MustRegister(collector)
		log.Info("Kernel conntrack collector registered")
	}

	// Register Cilium conntrack collector
	if ciliumReader != nil {
		ciliumCollector := metrics.NewCiliumCollector(ciliumReader, podResolver, metricBreakdown, nodeName)
		prometheus.MustRegister(ciliumCollector)
		log.Info("Cilium conntrack collector registered")
	}

	// Start HTTP server
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	addr := ":" + metricsPort
	server := &http.Server{Addr: addr, Handler: mux}

	go func() {
		log.Infof("Serving metrics on %s/metrics", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Wait for SIGTERM/SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	log.Infof("Received signal %v, shutting down", sig)

	close(stopCh)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
	log.Info("Shutdown complete")
}
