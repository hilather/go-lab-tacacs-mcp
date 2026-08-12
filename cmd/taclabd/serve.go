package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hilather/go-lab-tacacs-mcp/internal/aaa"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/auth"
	mcpapi "github.com/hilather/go-lab-tacacs-mcp/internal/api/mcp"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/operations"
	"github.com/hilather/go-lab-tacacs-mcp/internal/api/rest"
	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/legacy"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
	tacacstls "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/tls"
)

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	path, err := parseConfigFlag(args)
	if err != nil {
		fmt.Fprintf(stderr, "taclabd serve: %v\n", err)
		return 2
	}
	if err := runServeWith(ctx, path, stdout, stderr, nil); err != nil {
		fmt.Fprintf(stderr, "taclabd serve: %v\n", err)
		return 1
	}
	return 0
}

func parseConfigFlag(args []string) (string, error) {
	var path string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config" || a == "-config":
			if i+1 >= len(args) {
				return "", fmt.Errorf("--config requires a path")
			}
			i++
			path = args[i]
		case len(a) > 9 && a[:9] == "--config=":
			path = a[9:]
		case a == "--":
			break
		case len(a) > 0 && a[0] == '-':
			return "", fmt.Errorf("unknown flag: %s", a)
		default:
			return "", fmt.Errorf("unexpected argument: %s", a)
		}
	}
	if path == "" {
		return "", fmt.Errorf("--config is required")
	}
	return path, nil
}

func runServe(ctx context.Context, path string, stdout, stderr io.Writer) error {
	return runServeWith(ctx, path, stdout, stderr, nil)
}

func runServeWith(ctx context.Context, path string, stdout, stderr io.Writer, h server.Handler) error {
	doc, err := config.Load(path)
	if err != nil {
		return err
	}
	if err := config.Validate(doc); err != nil {
		return err
	}
	legacyOn := doc.Listeners.LegacyTACACS.Enabled
	secureOn := doc.Listeners.SecureTACACS.Enabled
	if !legacyOn && !secureOn {
		return fmt.Errorf("at least one TACACS listener must be enabled")
	}

	lookup := secretLookup(doc)
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if legacyOn && secureOn {
		logger.Warn(operations.ColocatedTopologyWarning)
	}

	var ring *events.Ring
	if h == nil {
		var stdoutSink io.Writer
		if doc.Events.Stdout.Enabled {
			stdoutSink = stdout
		}
		ring = events.NewWithOptions(events.Options{
			Capacity:        doc.Events.RingBufferCapacity,
			Stdout:          stdoutSink,
			RedactUserInput: doc.Events.RedactUserInput,
		})
		aaaSvc, err := aaa.New(aaa.Options{Manager: mgr, Snapshot: mgr.Snapshot, Secrets: lookup, Events: ring})
		if err != nil {
			return err
		}
		h = server.Bridge{AAA: aaaSvc}
		defer ring.Close()
	}

	var legacyLn *legacy.Listener
	if legacyOn {
		legacyLn, err = legacy.Listen(legacy.Options{
			Bind:     doc.Listeners.LegacyTACACS.Bind,
			Settings: doc.Listeners.LegacyTACACS,
			Grace:    doc.Server.ShutdownGrace,
			Snapshot: mgr.Snapshot,
			Secrets:  lookup,
			Handler:  h,
			Logger:   logger,
		})
		if err != nil {
			return err
		}
	}

	var secureLn *tacacstls.Listener
	if secureOn {
		secureLn, err = tacacstls.Listen(tacacstls.Options{
			Bind:     doc.Listeners.SecureTACACS.Bind,
			Settings: doc.Listeners.SecureTACACS,
			Grace:    doc.Server.ShutdownGrace,
			Snapshot: mgr.Snapshot,
			Secrets:  lookup,
			Handler:  h,
			Logger:   logger,
		})
		if err != nil {
			if legacyLn != nil {
				_ = legacyLn.Shutdown(context.Background())
			}
			return err
		}
	}

	// serveCtx stops Accept only. Connection sessions use a detached drain context.
	serveCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-serveCtx.Done():
				return
			case <-hup:
				if err := reloadSnapshot(path, mgr); err != nil {
					logger.Error("reload rejected", "err", err)
				} else {
					logger.Info("reload published", "revision", uint64(mgr.Revision()))
				}
			}
		}
	}()

	errc := make(chan error, 3)
	if legacyLn != nil {
		go func() { errc <- legacyLn.Serve(serveCtx) }()
	}
	if secureLn != nil {
		go func() { errc <- secureLn.Serve(serveCtx) }()
	}

	var httpSrv *http.Server
	var httpLn net.Listener
	if doc.Listeners.HTTP.Enabled {
		httpSrv, httpLn, err = startHTTP(doc, mgr, lookup, legacyLn, secureLn, ring)
		if err != nil {
			if legacyLn != nil {
				_ = legacyLn.Shutdown(context.Background())
			}
			if secureLn != nil {
				_ = secureLn.Shutdown(context.Background())
			}
			return err
		}
		go func() { errc <- httpSrv.Serve(httpLn) }()
		fmt.Fprintf(stdout, "listening http %s\n", httpLn.Addr().String())
	}

	if legacyLn != nil {
		fmt.Fprintf(stdout, "listening legacy_tacacs %s\n", legacyLn.Addr().String())
	}
	if secureLn != nil {
		fmt.Fprintf(stdout, "listening secure_tacacs %s\n", secureLn.Addr().String())
	}
	fmt.Fprintln(stdout, "ready")

	var serveErr error
	select {
	case serveErr = <-errc:
	case <-serveCtx.Done():
		select {
		case serveErr = <-errc:
		default:
		}
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), doc.Server.ShutdownGrace)
	defer cancel()
	var shutErr error
	if httpSrv != nil {
		shutErr = httpSrv.Shutdown(shutCtx)
	}
	if legacyLn != nil {
		if err := legacyLn.Shutdown(shutCtx); err != nil && shutErr == nil {
			shutErr = err
		}
	}
	if secureLn != nil {
		if err := secureLn.Shutdown(shutCtx); err != nil && shutErr == nil {
			shutErr = err
		}
	}
	if serveErr != nil && serveCtx.Err() == nil && !isHTTPClosed(serveErr) {
		return serveErr
	}
	if shutErr != nil && shutCtx.Err() == nil {
		return shutErr
	}
	return nil
}

func isHTTPClosed(err error) bool {
	return err == http.ErrServerClosed
}

func startHTTP(doc *config.Document, mgr *state.Manager, lookup config.SecretLookup, legacyLn *legacy.Listener, secureLn *tacacstls.Listener, ring *events.Ring) (*http.Server, net.Listener, error) {
	reg, err := loadRegistry(operations.BuildMeta{Version: version, Commit: commit, BuildTime: buildTime}, ring)
	if err != nil {
		return nil, nil, err
	}
	verifier, err := auth.Load(doc, lookup, nil)
	if err != nil {
		return nil, nil, err
	}
	ready := func() bool {
		if mgr.Snapshot() == nil {
			return false
		}
		if legacyLn == nil && secureLn == nil {
			return false
		}
		return true
	}
	restSrv := &rest.Server{
		Registry: reg,
		Snapshot: mgr.Snapshot,
		Auth:     verifier,
		Ready:    ready,
		MaxBody:  doc.Listeners.HTTP.MaxRequestBodyBytes,
	}
	mux := http.NewServeMux()
	mcpH := mcpapi.Handler(mcpapi.Options{
		Registry: reg,
		Snapshot: mgr.Snapshot,
		Auth:     verifier,
		MCP:      doc.API.MCP,
		Version:  version,
	})
	mux.Handle("/mcp", mcpH)
	mux.Handle("/mcp/", mcpH)
	mux.Handle("/", restSrv.Handler())

	ln, err := net.Listen("tcp", doc.Listeners.HTTP.Bind)
	if err != nil {
		return nil, nil, err
	}
	hs := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: doc.Listeners.HTTP.ReadHeaderTimeout,
		ReadTimeout:       doc.Listeners.HTTP.ReadTimeout,
		WriteTimeout:      doc.Listeners.HTTP.WriteTimeout,
		IdleTimeout:       doc.Listeners.HTTP.IdleTimeout,
	}
	if hs.ReadHeaderTimeout == 0 {
		hs.ReadHeaderTimeout = 5 * time.Second
	}
	return hs, ln, nil
}

func loadRegistry(meta operations.BuildMeta, ring *events.Ring) (*operations.Registry, error) {
	deps := operations.Deps{Build: meta, Events: ring}
	if reg, err := operations.NewFromRepo(".", deps); err == nil {
		return reg, nil
	}
	if exe, err := os.Executable(); err == nil {
		if reg, err := operations.NewFromRepo(filepath.Dir(exe), deps); err == nil {
			return reg, nil
		}
	}
	return operations.NewFromRepo("/", deps)
}

func reloadSnapshot(path string, mgr *state.Manager) error {
	doc, err := config.Load(path)
	if err != nil {
		return err
	}
	if err := config.Validate(doc); err != nil {
		return err
	}
	rev := mgr.Revision()
	_, err = mgr.Reload(doc, &rev)
	return err
}

func secretLookup(doc *config.Document) config.SecretLookup {
	opts := config.ReadOptions{
		AllowEnvironment: doc.Security.AllowEnvironmentSecrets,
		StrictFiles:      doc.Security.StrictSecretFiles,
		StrictFilesSet:   true,
	}
	return func(ref config.SecretRef) ([]byte, error) {
		_, holder, err := config.ReadSecret(ref, opts)
		if err != nil {
			return nil, err
		}
		switch s := holder.(type) {
		case credentials.SharedSecret:
			return s.Bytes(), nil
		case credentials.LoginVerifier:
			return s.Bytes(), nil
		case credentials.ChallengeSecret:
			return s.Bytes(), nil
		case credentials.EnableVerifier:
			return s.Bytes(), nil
		case credentials.TokenMaterial:
			return s.Bytes(), nil
		case credentials.TLSPrivateKey:
			return s.Bytes(), nil
		default:
			return nil, fmt.Errorf("unsupported secret purpose")
		}
	}
}
