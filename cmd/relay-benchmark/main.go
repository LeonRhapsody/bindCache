package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	duration time.Duration
	ok       bool
	canceled bool
}

func main() {
	url := flag.String("url", "", "relay base URL, e.g. https://127.0.0.1:18787")
	resolver := flag.String("resolver", "114.114.114.114:53", "DNS resolver queried by relay")
	domain := flag.String("domain", "example.com.", "stable cached test domain")
	levelsRaw := flag.String("concurrency", "1,2,4,8,12,16,24,32", "comma-separated concurrency levels")
	duration := flag.Duration("duration", 10*time.Second, "duration per level")
	maxRequests := flag.Int("max-requests", 500, "safety cap per level")
	dnsTimeout := flag.Duration("dns-timeout", 2*time.Second, "relay DNS timeout")
	caPath := flag.String("ca", "", "PEM CA for relay TLS")
	insecure := flag.Bool("insecure", false, "skip TLS verification; benchmark only")
	tasksPerEvent := flag.Float64("tasks-per-event", 14.08, "logical DNS tasks per event for capacity conversion")
	flag.Parse()
	if strings.TrimSpace(*url) == "" {
		fatal("-url is required")
	}
	token := strings.TrimSpace(os.Getenv("NS_RELAY_TOKEN"))
	if token == "" {
		fatal("NS_RELAY_TOKEN is not set")
	}
	if *duration < time.Second || *duration > time.Minute {
		fatal("-duration must be between 1s and 1m")
	}
	if *maxRequests < 1 || *maxRequests > 10000 {
		fatal("-max-requests must be between 1 and 10000")
	}
	levels := parseLevels(*levelsRaw)
	if len(levels) == 0 {
		fatal("no valid concurrency levels")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: *insecure} // #nosec G402 -- explicit benchmark flag
	if *caPath != "" {
		raw, err := os.ReadFile(*caPath)
		if err != nil {
			fatal(err.Error())
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(raw) {
			fatal("CA file has no certificate")
		}
		tlsConfig.RootCAs = roots
	}
	transport := &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: tlsConfig, MaxIdleConns: 256, MaxIdleConnsPerHost: 256, MaxConnsPerHost: 256, IdleConnTimeout: 30 * time.Second}
	client := &http.Client{Transport: transport, Timeout: time.Duration(len([]string{"A", "AAAA"})*2)*(*dnsTimeout) + 3*time.Second}
	endpoint := strings.TrimRight(*url, "/") + "/v1/dns-probe"
	payload, _ := json.Marshal(map[string]any{"domain": *domain, "resolver": *resolver, "recursive": true, "types": []string{"A", "AAAA"}, "timeout_ms": dnsTimeout.Milliseconds()})
	if r := one(context.Background(), client, endpoint, token, payload); !r.ok {
		fatal("warm-up request failed; verify URL, token, CA and resolver")
	}
	fmt.Println("concurrency completed ok errors canceled req/s dns_queries/s event_equiv/s p50 p95 p99")
	for _, level := range levels {
		runLevel(client, endpoint, token, payload, level, *duration, *maxRequests, *tasksPerEvent)
	}
}

func runLevel(client *http.Client, endpoint, token string, payload []byte, concurrency int, duration time.Duration, maxRequests int, tasksPerEvent float64) {
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	started := time.Now()
	results := make(chan result, maxRequests)
	var issued atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := issued.Add(1)
				if n > int64(maxRequests) {
					return
				}
				select {
				case <-ctx.Done():
					return
				default:
				}
				results <- one(ctx, client, endpoint, token, payload)
			}
		}()
	}
	wg.Wait()
	close(results)
	elapsed := time.Since(started)
	values := make([]time.Duration, 0)
	okCount, errors, canceled := 0, 0, 0
	for value := range results {
		if value.canceled {
			canceled++
			continue
		}
		values = append(values, value.duration)
		if value.ok {
			okCount++
		} else {
			errors++
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	count := len(values)
	rps := float64(okCount) / elapsed.Seconds()
	fmt.Printf("%d %d %d %d %d %.2f %.2f %.3f %s %s %s\n", concurrency, count, okCount, errors, canceled, rps, rps*2, rps/tasksPerEvent, percentile(values, .50), percentile(values, .95), percentile(values, .99))
}

func one(ctx context.Context, client *http.Client, endpoint, token string, payload []byte) result {
	started := time.Now()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return result{duration: time.Since(started)}
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return result{duration: time.Since(started), canceled: ctx.Err() != nil}
	}
	defer response.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 256<<10))
	return result{duration: time.Since(started), ok: err == nil && response.StatusCode == http.StatusOK}
}

func percentile(values []time.Duration, p float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values)-1) * p)
	return values[index].Round(time.Millisecond)
}
func parseLevels(raw string) []int {
	seen := map[int]struct{}{}
	out := []int{}
	for _, part := range strings.Split(raw, ",") {
		value, err := strconv.Atoi(strings.TrimSpace(part))
		if err == nil && value > 0 && value <= 256 {
			if _, ok := seen[value]; !ok {
				seen[value] = struct{}{}
				out = append(out, value)
			}
		}
	}
	sort.Ints(out)
	return out
}
func fatal(message string) { fmt.Fprintln(os.Stderr, "relay benchmark:", message); os.Exit(1) }
