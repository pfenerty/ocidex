package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

// measureOptions configure "loadgen measure", which times GET routes against a
// running instance (ocidex-xxee.5).
type measureOptions struct {
	url     string
	apiKey  string
	routes  string
	samples int
	timeout time.Duration
}

// routeResult is one route's latency over its samples.
type routeResult struct {
	Name, Path string
	P50, P95   time.Duration
	Max        time.Duration
	Status     int // the last sample's status
	Errors     int // samples that failed or returned a status >= 400
}

func parseMeasureFlags(args []string) measureOptions {
	var o measureOptions
	fs := flag.NewFlagSet("loadgen measure", flag.ExitOnError)
	fs.StringVar(&o.url, "url", "http://localhost:8080", "API base URL")
	fs.StringVar(&o.apiKey, "api-key", os.Getenv("OCIDEX_API_KEY"), "API key (default $OCIDEX_API_KEY)")
	fs.StringVar(&o.routes, "routes", "", "file of \"<route> <path>\" lines, one per request to time; # starts a comment")
	fs.IntVar(&o.samples, "samples", 20, "timed requests per route, after one untimed warm-up")
	fs.DurationVar(&o.timeout, "timeout", 60*time.Second, "per-request timeout")
	_ = fs.Parse(args)
	return o
}

func runMeasure(ctx context.Context, o measureOptions, out io.Writer) error {
	if o.routes == "" || o.samples < 1 {
		return errors.New("measure needs -routes and -samples >= 1")
	}
	routes, err := readRoutes(o.routes)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: o.timeout}
	results := make([]routeResult, 0, len(routes))
	for _, r := range routes {
		res, err := measureRoute(ctx, c, o, r[0], r[1])
		if err != nil {
			return err
		}
		results = append(results, res)
	}
	writeTable(out, results)
	return nil
}

func readRoutes(path string) ([][2]string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: an operator-supplied file is the point
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][2]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, path, ok := strings.Cut(line, " ")
		if !ok {
			return nil, fmt.Errorf("route line %q: want \"<route> <path>\"", line)
		}
		out = append(out, [2]string{name, strings.TrimSpace(path)})
	}
	return out, sc.Err()
}

func measureRoute(ctx context.Context, c *http.Client, o measureOptions, name, path string) (routeResult, error) {
	res := routeResult{Name: name, Path: path}
	durations := make([]time.Duration, 0, o.samples)
	for i := range o.samples + 1 {
		d, status, err := get(ctx, c, o, path)
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if i == 0 {
			continue // warm-up: connection setup and cold caches
		}
		res.Status = status
		if err != nil || status >= 400 {
			res.Errors++
		}
		durations = append(durations, d)
	}
	slices.Sort(durations)
	res.P50 = percentile(durations, 0.50)
	res.P95 = percentile(durations, 0.95)
	res.Max = durations[len(durations)-1]
	return res, nil
}

func get(ctx context.Context, c *http.Client, o measureOptions, path string) (time.Duration, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimSuffix(o.url, "/")+path, nil)
	if err != nil {
		return 0, 0, err
	}
	if o.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.apiKey)
	}
	start := time.Now()
	resp, err := c.Do(req)
	if err != nil {
		return time.Since(start), 0, err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return time.Since(start), resp.StatusCode, nil
}

// percentile is the nearest-rank percentile of sorted durations.
func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(p*float64(len(sorted))+0.999999) - 1
	return sorted[min(max(rank, 0), len(sorted)-1)]
}

// writeTable prints the results as a Markdown table, slowest p95 first.
func writeTable(out io.Writer, results []routeResult) {
	slices.SortStableFunc(results, func(a, b routeResult) int { return int(b.P95 - a.P95) })
	fmt.Fprintln(out, "| Route | p50 | p95 | max | status |")
	fmt.Fprintln(out, "|---|---:|---:|---:|---|")
	for _, r := range results {
		status := fmt.Sprint(r.Status)
		if r.Errors > 0 {
			status = fmt.Sprintf("%d (%d errors)", r.Status, r.Errors)
		}
		fmt.Fprintf(out, "| `%s` | %s | %s | %s | %s |\n", r.Name, ms(r.P50), ms(r.P95), ms(r.Max), status)
	}
}

func ms(d time.Duration) string {
	if d >= time.Second {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}
