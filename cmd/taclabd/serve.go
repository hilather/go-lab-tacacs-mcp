package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/hilather/go-lab-tacacs-mcp/internal/config"
	"github.com/hilather/go-lab-tacacs-mcp/internal/credentials"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/legacy"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
)

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	path, err := parseConfigFlag(args)
	if err != nil {
		fmt.Fprintf(stderr, "taclabd serve: %v\n", err)
		return 2
	}
	if err := runServe(ctx, path, stdout, stderr); err != nil {
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
	doc, err := config.Load(path)
	if err != nil {
		return err
	}
	if err := config.Validate(doc); err != nil {
		return err
	}
	if !doc.Listeners.LegacyTACACS.Enabled {
		return fmt.Errorf("listeners.legacy_tacacs is disabled")
	}

	lookup := secretLookup(doc)
	mgr, err := state.New(doc, state.Options{Secrets: lookup})
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if doc.Listeners.SecureTACACS.Enabled {
		logger.Warn("listeners.secure_tacacs is not implemented; TLS listener skipped")
	}
	if doc.Listeners.HTTP.Enabled {
		logger.Warn("listeners.http is not implemented; admin listener skipped")
	}

	ln, err := legacy.Listen(legacy.Options{
		Bind:     doc.Listeners.LegacyTACACS.Bind,
		Settings: doc.Listeners.LegacyTACACS,
		Grace:    doc.Server.ShutdownGrace,
		Snapshot: mgr.Snapshot,
		Secrets:  lookup,
		Handler:  server.Stub{},
		Logger:   logger,
	})
	if err != nil {
		return err
	}

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

	errc := make(chan error, 1)
	go func() { errc <- ln.Serve(serveCtx) }()

	fmt.Fprintf(stdout, "listening legacy_tacacs %s\n", ln.Addr().String())
	fmt.Fprintln(stdout, "ready")

	select {
	case err := <-errc:
		if err != nil && serveCtx.Err() == nil {
			return err
		}
	case <-serveCtx.Done():
	}

	shutCtx, cancel := context.WithTimeout(context.Background(), doc.Server.ShutdownGrace)
	defer cancel()
	if err := ln.Shutdown(shutCtx); err != nil && shutCtx.Err() == nil {
		return err
	}
	return nil
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
