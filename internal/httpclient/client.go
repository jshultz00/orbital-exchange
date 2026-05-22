// Package httpclient is the single HTTP entry point every check uses.
//
// Centralising HTTP into one place gives the scanner three properties that
// matter in a real engagement:
//
//  1. A consistent, identifying User-Agent on every request, so the target's
//     logs unambiguously attribute traffic to the tool.
//  2. A global rate limit, so an enthusiastic check can't accidentally hammer
//     the target.
//  3. A single redirect/timeout/TLS policy, so the *output* of any check is
//     comparable regardless of which network conditions it hit.
//
// LEARNING NOTE: when reviewers look at a scanner repo, the first thing they
// open is the HTTP layer. Sloppy timeouts and "follow redirects everywhere"
// are tells of an amateur tool; explicit policies here are a strong signal.
package httpclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jshultz/vulnscope/internal/scanner"
)

// tokenBucket is a hand-rolled rate limiter: one request released every
// `interval`. Sufficient for a sequential scanner and keeps the module deps
// to zero. Replace with golang.org/x/time/rate if/when checks run concurrently.
type tokenBucket struct {
	interval time.Duration
	next     time.Time
}

func newTokenBucket(perSec float64) *tokenBucket {
	if perSec <= 0 {
		return nil
	}
	return &tokenBucket{interval: time.Duration(float64(time.Second) / perSec)}
}

func (b *tokenBucket) wait() {
	now := time.Now()
	if b.next.After(now) {
		time.Sleep(b.next.Sub(now))
	}
	b.next = time.Now().Add(b.interval)
}

// Config tunes the shared client. Zero values are safe defaults.
type Config struct {
	UserAgent      string        // default "vulnscope/0.1"
	Timeout        time.Duration // default 10s
	RatePerSec     float64       // 0 = no limit
	FollowRedirect bool          // default false — IDOR/header checks need raw responses
	InsecureTLS    bool          // default false — set true only against self-signed labs
}

// Client wraps *http.Client with a rate limiter and the scanner-internal
// request/response types.
type Client struct {
	cfg     Config
	hc      *http.Client
	limiter *tokenBucket
}

// New builds a Client from cfg.
func New(cfg Config) *Client {
	if cfg.UserAgent == "" {
		cfg.UserAgent = "vulnscope/0.1 (+https://github.com/jshultz/vulnscope)"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	hc := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureTLS},
		},
	}
	if !cfg.FollowRedirect {
		hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return &Client{cfg: cfg, hc: hc, limiter: newTokenBucket(cfg.RatePerSec)}
}

// Do issues a request through the shared client. Implements scanner.HTTPDoer.
func (c *Client) Do(req *scanner.HTTPRequest) (*scanner.HTTPResponse, error) {
	if c.limiter != nil {
		c.limiter.wait()
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}
	hr, err := http.NewRequest(method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	hr.Header.Set("User-Agent", c.cfg.UserAgent)
	for k, v := range req.Headers {
		hr.Header.Set(k, v)
	}
	resp, err := c.hc.Do(hr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024)) // 4 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return &scanner.HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       b,
		URL:        hr.URL.String(),
	}, nil
}
