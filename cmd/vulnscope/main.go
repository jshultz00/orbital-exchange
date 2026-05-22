// Command vulnscope is the CLI entry point.
//
// Usage:
//
//	vulnscope --target http://localhost:3000 \
//	          --checks a05,a03 \
//	          --output terminal,json,md \
//	          --out-dir 02-findings/raw \
//	          --rate 10 --timeout 10s
//
// Phase A ships the skeleton: argument parsing, the scan orchestrator, and
// all three reporters. Detection modules are registered in registerChecks
// below as they come online (A05 → A03 → A01 → A06).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jshultz/vulnscope/internal/httpclient"
	"github.com/jshultz/vulnscope/internal/report"
	"github.com/jshultz/vulnscope/internal/scanner"
)

// version is overridden at build time: `go build -ldflags "-X main.version=..."`.
var version = "0.1.0-dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		target  = flag.String("target", "", "Base URL of the system under test (required)")
		checks  = flag.String("checks", "", "Comma-separated check IDs or OWASP categories (e.g. 'a05,a03'). Empty = all.")
		outputs = flag.String("output", "terminal", "Comma-separated output formats: terminal,json,md")
		outDir  = flag.String("out-dir", "02-findings/raw", "Directory for json/md output")
		rate    = flag.Float64("rate", 10, "Max requests per second (0 = unlimited)")
		timeout = flag.Duration("timeout", 60*time.Second, "Overall scan timeout")
		ua      = flag.String("user-agent", "", "Override the User-Agent (default: vulnscope/<version>)")
		insec   = flag.Bool("insecure", false, "Skip TLS verification (lab use only)")
		list    = flag.Bool("list", false, "List registered checks and exit")
		ver     = flag.Bool("version", false, "Print version and exit")
		verbose = flag.Bool("verbose", false, "Verbose logging")
	)
	flag.Parse()

	if *ver {
		fmt.Println("vulnscope", version)
		return nil
	}

	logger := newStdLogger(*verbose)
	allChecks := registerChecks()

	if *list {
		fmt.Println("registered checks:")
		for _, c := range allChecks {
			fmt.Printf("  %-32s %s  %s\n", c.ID(), c.OWASPCategory(), c.Description())
		}
		if len(allChecks) == 0 {
			fmt.Println("  (none — detection modules wire up in Phase B+)")
		}
		return nil
	}

	if *target == "" {
		flag.Usage()
		return fmt.Errorf("--target is required")
	}

	t, err := scanner.NewTarget(*target)
	if err != nil {
		return err
	}

	hcCfg := httpclient.Config{
		UserAgent:   *ua,
		Timeout:     10 * time.Second,
		RatePerSec:  *rate,
		InsecureTLS: *insec,
	}
	client := httpclient.New(hcCfg)

	enabled := splitCSV(*checks)
	s := scanner.New(t, allChecks, enabled, scanner.Deps{HTTP: client, Logger: logger})

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx = withSignalCancel(ctx)

	result := s.Run(ctx)

	formats := splitCSV(*outputs)
	if len(formats) == 0 {
		formats = []string{"terminal"}
	}
	if err := emitReports(formats, *outDir, result); err != nil {
		return err
	}
	return nil
}

func registerChecks() []scanner.Check {
	// Detection modules are appended here as each phase lands:
	//   Phase B: a05_misconfig
	//   Phase C: a03_injection
	//   Phase D: a01_access
	//   Phase E: a06_components
	return nil
}

func emitReports(formats []string, outDir string, r *scanner.Result) error {
	for _, f := range formats {
		switch strings.ToLower(strings.TrimSpace(f)) {
		case "terminal", "term", "":
			report.Terminal(os.Stdout, r, isTTY(os.Stdout))
		case "json":
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			path := filepath.Join(outDir, "scan.json")
			file, err := os.Create(path)
			if err != nil {
				return err
			}
			err = report.JSON(file, r)
			file.Close()
			if err != nil {
				return fmt.Errorf("write json: %w", err)
			}
			fmt.Fprintln(os.Stderr, "wrote", path)
		case "md", "markdown":
			if err := report.Markdown(outDir, r); err != nil {
				return fmt.Errorf("write markdown: %w", err)
			}
			fmt.Fprintln(os.Stderr, "wrote markdown findings to", outDir)
		default:
			return fmt.Errorf("unknown output format: %q", f)
		}
	}
	return nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func withSignalCancel(parent context.Context) context.Context {
	ctx, cancel := context.WithCancel(parent)
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// stdLogger is a tiny wrapper around the standard library logger that
// satisfies scanner.Logger. We define it inline rather than reaching for a
// structured logging library — keeping deps to zero.
type stdLogger struct {
	verbose bool
	l       *log.Logger
}

func newStdLogger(verbose bool) *stdLogger {
	return &stdLogger{verbose: verbose, l: log.New(os.Stderr, "", log.LstdFlags)}
}

func (s *stdLogger) Debugf(f string, a ...any) {
	if s.verbose {
		s.l.Printf("debug: "+f, a...)
	}
}
func (s *stdLogger) Infof(f string, a ...any)  { s.l.Printf("info:  "+f, a...) }
func (s *stdLogger) Warnf(f string, a ...any)  { s.l.Printf("warn:  "+f, a...) }
