package ebpf

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// CachedCiliumReader wraps a CiliumReader with an async background refresh.
// Scrapes read the cached result instantly — zero latency, predictable CPU.
type CachedCiliumReader struct {
	inner    CiliumReader
	interval time.Duration

	mu     sync.RWMutex
	cached *CiliumReadResult

	stopCh chan struct{}
	done   chan struct{}
}

// NewCachedCiliumReader creates a cached wrapper around any CiliumReader.
// It performs one synchronous read immediately, then refreshes in the
// background at the given interval. Returns an error only if the initial
// read fails.
func NewCachedCiliumReader(inner CiliumReader, interval time.Duration) (*CachedCiliumReader, error) {
	// Initial synchronous read so the first scrape has data.
	result, err := inner.ReadCounts()
	if err != nil {
		return nil, err
	}

	c := &CachedCiliumReader{
		inner:    inner,
		interval: interval,
		cached:   result,
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}

	go c.refreshLoop()
	log.Infof("Cilium CT cache started (refresh every %s)", interval)
	return c, nil
}

// ReadCounts returns the most recently cached result.
func (c *CachedCiliumReader) ReadCounts() (*CiliumReadResult, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cached, nil
}

// Close stops the background goroutine and closes the inner reader.
func (c *CachedCiliumReader) Close() error {
	close(c.stopCh)
	<-c.done
	return c.inner.Close()
}

func (c *CachedCiliumReader) refreshLoop() {
	defer close(c.done)
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			result, err := c.inner.ReadCounts()
			if err != nil {
				log.Warnf("Cilium CT cache refresh failed (keeping previous): %v", err)
				continue
			}
			c.mu.Lock()
			c.cached = result
			c.mu.Unlock()
		}
	}
}
