package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

func main() {
	bytesToDownload := flag.Int64("bytes", 25*1024*1024, "number of bytes to download")
	timeout := flag.Duration("timeout", 90*time.Second, "benchmark timeout")
	flag.Parse()

	if *bytesToDownload <= 0 {
		fmt.Fprintln(os.Stderr, "bytes must be positive")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	client := &http.Client{}

	ip, err := fetchText(ctx, client, "https://api.ipify.org")
	if err != nil {
		fmt.Fprintf(os.Stderr, "public IP check failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Public IP: %s\n", strings.TrimSpace(ip))

	latencies, failures := measureHTTPSLatency(ctx, client, "https://cloudflare.com/cdn-cgi/trace", 5)
	if len(latencies) > 0 {
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		median := latencies[len(latencies)/2]
		fmt.Printf("HTTPS latency median: %.0f ms (%d/%d successful)\n", float64(median.Microseconds())/1000, len(latencies), len(latencies)+failures)
	} else {
		fmt.Printf("HTTPS latency: unavailable (0/%d successful)\n", failures)
	}

	url := fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", *bytesToDownload)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	start := time.Now()
	rsp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download failed: %v\n", err)
		os.Exit(1)
	}
	defer rsp.Body.Close()
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		fmt.Fprintf(os.Stderr, "download failed: %s\n", rsp.Status)
		os.Exit(1)
	}
	n, err := io.Copy(io.Discard, rsp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "download read failed: %v\n", err)
		os.Exit(1)
	}
	elapsed := time.Since(start)
	mbit := float64(n*8) / elapsed.Seconds() / 1_000_000
	mib := float64(n) / 1024 / 1024
	fmt.Printf("Downloaded: %.2f MiB\n", mib)
	fmt.Printf("Time: %.2f s\n", elapsed.Seconds())
	fmt.Printf("Speed: %.2f Mbit/s\n", mbit)
}

func fetchText(ctx context.Context, client *http.Client, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	rsp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer rsp.Body.Close()
	if rsp.StatusCode < 200 || rsp.StatusCode > 299 {
		return "", fmt.Errorf("%s", rsp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(rsp.Body, 4096))
	if err != nil {
		return "", err
	}
	return string(b), nil
}


func measureHTTPSLatency(ctx context.Context, client *http.Client, url string, attempts int) ([]time.Duration, int) {
	latencies := make([]time.Duration, 0, attempts)
	failures := 0
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			failures++
			continue
		}
		req.Header.Set("Cache-Control", "no-cache")
		start := time.Now()
		rsp, err := client.Do(req)
		if err != nil {
			failures++
			continue
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(rsp.Body, 64*1024))
		closeErr := rsp.Body.Close()
		if rsp.StatusCode < 200 || rsp.StatusCode > 399 || readErr != nil || closeErr != nil {
			failures++
			continue
		}
		latencies = append(latencies, time.Since(start))
	}
	return latencies, failures
}
