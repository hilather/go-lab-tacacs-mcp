package main

import (
	"context"
	"crypto/rand"
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
	"github.com/hilather/go-lab-tacacs-mcp/internal/domain"
	"github.com/hilather/go-lab-tacacs-mcp/internal/events"
	"github.com/hilather/go-lab-tacacs-mcp/internal/observability"
	radiusruntime "github.com/hilather/go-lab-tacacs-mcp/internal/radius/runtime"
	radiusserver "github.com/hilather/go-lab-tacacs-mcp/internal/radius/server"
	radiusudp "github.com/hilather/go-lab-tacacs-mcp/internal/radius/udp"
	"github.com/hilather/go-lab-tacacs-mcp/internal/runtime"
	"github.com/hilather/go-lab-tacacs-mcp/internal/state"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/legacy"
	"github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/server"
	tacacstls "github.com/hilather/go-lab-tacacs-mcp/internal/tacacs/tls"
)

var _ operations.StatusProvider = (*runtime.Registry)(nil)

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
args:
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
			break args
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
	accessOn := doc.Listeners.RADIUSAccess.Enabled
	acctOn := doc.Listeners.RADIUSAccounting.Enabled
	if !legacyOn && !secureOn && !accessOn && !acctOn && !doc.Server.AdminOnly {
		return fmt.Errorf("at least one AAA listener must be enabled")
	}

	obs := observability.New(observability.Options{
		MetricsEnabled: doc.Observability.Metrics.Enabled,
		MetricsBind:    doc.Observability.Metrics.Bind,
		MetricsPath:    doc.Observability.Metrics.Path,
		ExposeOnAdmin:  doc.Observability.Metrics.ExposeOnAdmin,
		TracingEnabled: doc.Observability.Tracing.Enabled,
		PprofEnabled:   doc.Observability.Profiling.Enabled,
	})
	observeSnap := func(snap *state.Snapshot) {
		if snap == nil {
			return
		}
		obs.Rec.SetRevision(uint64(snap.Revision))
		counts := map[string]int{}
		for st, n := range snap.LifecycleCounts() {
			counts[string(st)] = n
		}
		obs.Rec.SetSecretLifecycle(counts)
	}

	lookup := secretLookup(doc)
	mgr, err := state.New(doc, state.Options{Secrets: lookup, Hook: observeSnap})
	if err != nil {
		return err
	}
	observeSnap(mgr.Snapshot())
	emitLifecycleWarnings(obs.Rec, mgr.Snapshot())

	logger := observability.NewJSONLogger(stderr, observability.ParseLogLevel(doc.Server.LogLevel))
	if legacyOn && secureOn {
		logger.Warn(operations.ColocatedTopologyWarning)
	}

	var ring *events.Ring
	var aaaSvc *aaa.Service
	if h == nil {
		var stdoutSink io.Writer
		if doc.Events.Stdout.Enabled {
			stdoutSink = stdout
		}
		ring = events.NewWithOptions(events.Options{
			Capacity:        doc.Events.RingBufferCapacity,
			Stdout:          stdoutSink,
			RedactUserInput: doc.Events.RedactUserInput,
			Metrics:         obs.Rec,
		})
		sessIdx, err := newRADIUSSessionIndex(doc, obs.Rec)
		if err != nil {
			return err
		}
		aaaSvc, err = aaa.New(aaa.Options{Manager: mgr, Snapshot: mgr.Snapshot, Secrets: lookup, Events: ring, Metrics: obs.Rec, Sessions: sessIdx})
		if err != nil {
			return err
		}
		h = server.Bridge{AAA: aaaSvc}
		defer ring.Close()
	}
	challenges := radiusruntime.NewChallengeStoreWithHook(
		doc.Listeners.RADIUSAccess.ChallengeEntries,
		doc.Listeners.RADIUSAccess.ChallengeBytes,
		doc.Listeners.RADIUSAccess.ChallengeTTL,
		nil,
		obs.Rec.RADIUSChallengeSaturation,
	)
	var radiusAccess radiusserver.Handler = radiusserver.Stub{}
	if aaaSvc != nil {
		radiusAccess = radiusserver.Access{AAA: aaaSvc, Store: challenges}
	}

	var built []runtime.Listener
	cleanup := func() {
		for i := len(built) - 1; i >= 0; i-- {
			_ = built[i].Close()
		}
	}
	if legacyOn {
		legacyLn, err := legacy.Listen(legacy.Options{
			Bind:     doc.Listeners.LegacyTACACS.Bind,
			Settings: doc.Listeners.LegacyTACACS,
			Grace:    doc.Server.ShutdownGrace,
			Snapshot: mgr.Snapshot,
			Secrets:  lookup,
			Handler:  h,
			Logger:   logger,
			Metrics:  obs.Rec,
		})
		if err != nil {
			return err
		}
		built = append(built, legacyLn)
	}
	if secureOn {
		secureLn, err := tacacstls.Listen(tacacstls.Options{
			Bind:     doc.Listeners.SecureTACACS.Bind,
			Settings: doc.Listeners.SecureTACACS,
			Grace:    doc.Server.ShutdownGrace,
			Snapshot: mgr.Snapshot,
			Secrets:  lookup,
			Handler:  h,
			Logger:   logger,
			Metrics:  obs.Rec,
		})
		if err != nil {
			cleanup()
			return err
		}
		built = append(built, secureLn)
	}
	if accessOn {
		accessLn, err := radiusudp.Listen(radiusudp.Options{
			ID:         runtime.IDRADIUSAccess,
			Role:       domain.RoleAccess,
			Bind:       doc.Listeners.RADIUSAccess.Bind,
			Required:   doc.Listeners.RADIUSAccess.Required,
			Settings:   doc.Listeners.RADIUSAccess,
			Snapshot:   mgr.Snapshot,
			Secrets:    lookup,
			Handler:    radiusAccess,
			Logger:     logger,
			Metrics:    obs.Rec,
			Challenges: challenges,
		})
		if err != nil {
			cleanup()
			return err
		}
		built = append(built, accessLn)
	}
	if acctOn {
		acctLn, err := radiusudp.Listen(radiusudp.Options{
			ID:       runtime.IDRADIUSAccounting,
			Role:     domain.RoleAccounting,
			Bind:     doc.Listeners.RADIUSAccounting.Bind,
			Required: doc.Listeners.RADIUSAccounting.Required,
			Settings: doc.Listeners.RADIUSAccounting,
			Snapshot: mgr.Snapshot,
			Secrets:  lookup,
			Recorder: aaaSvc,
			Logger:   logger,
			Metrics:  obs.Rec,
		})
		if err != nil {
			cleanup()
			return err
		}
		built = append(built, acctLn)
	}
	listeners, err := runtime.New(built...)
	if err != nil {
		cleanup()
		return err
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
					obs.Rec.Reload(false)
					logger.Error("reload rejected", "err", err)
				} else {
					obs.Rec.Reload(true)
					emitLifecycleWarnings(obs.Rec, mgr.Snapshot())
					logger.Info("reload published", "revision", uint64(mgr.Revision()))
				}
			}
		}
	}()

	extra := 0
	if obs.NeedsListener() {
		extra++
	}
	if doc.Listeners.HTTP.Enabled {
		extra++
	}
	errc := make(chan error, listeners.Len()+extra)
	if err := listeners.Start(serveCtx, errc); err != nil {
		cleanup()
		return err
	}
	if obs.NeedsListener() {
		if err := obs.Listen(); err != nil {
			_ = listeners.Drain(context.Background())
			return err
		}
		go func() { errc <- obs.Serve(serveCtx) }()
		if addr := obs.Addr(); addr != nil {
			fmt.Fprintf(stdout, "listening metrics %s\n", addr.String())
		}
	}

	var httpSrv *http.Server
	var httpLn net.Listener
	if doc.Listeners.HTTP.Enabled {
		httpSrv, httpLn, err = startHTTP(path, doc, mgr, lookup, listeners, ring, aaaSvc, logger, obs, challenges.Reset)
		if err != nil {
			_ = listeners.Drain(context.Background())
			return err
		}
		go func() { errc <- httpSrv.Serve(httpLn) }()
		fmt.Fprintf(stdout, "listening http %s\n", httpLn.Addr().String())
	}

	if l := listeners.Get(runtime.IDLegacyTACACS); l != nil {
		fmt.Fprintf(stdout, "listening legacy_tacacs %s\n", l.Status().Bind)
	}
	if l := listeners.Get(runtime.IDSecureTACACS); l != nil {
		fmt.Fprintf(stdout, "listening secure_tacacs %s\n", l.Status().Bind)
	}
	if l := listeners.Get(runtime.IDRADIUSAccess); l != nil {
		fmt.Fprintf(stdout, "listening radius_access %s\n", l.Status().Bind)
	}
	if l := listeners.Get(runtime.IDRADIUSAccounting); l != nil {
		fmt.Fprintf(stdout, "listening radius_accounting %s\n", l.Status().Bind)
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
	if err := obs.Shutdown(shutCtx); err != nil && shutErr == nil {
		shutErr = err
	}
	if err := listeners.Drain(shutCtx); err != nil && shutErr == nil {
		shutErr = err
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

func startHTTP(configPath string, doc *config.Document, mgr *state.Manager, lookup config.SecretLookup, listeners *runtime.Registry, ring *events.Ring, aaaSvc *aaa.Service, logger *slog.Logger, obs *observability.Server, onReset func()) (*http.Server, net.Listener, error) {
	if obs == nil {
		obs = observability.New(observability.Options{})
	}
	if err := auth.LoadBootstrap(mgr.Snapshot(), lookup); err != nil {
		return nil, nil, err
	}
	authSvc := auth.New(auth.Options{})
	creds, err := credentials.NewService(credentials.NewMemory(), credentials.Options{})
	if err != nil {
		return nil, nil, err
	}
	var sessIdx *radiusruntime.SessionIndex
	var originator *radiusserver.Originator
	if aaaSvc != nil {
		sessIdx = aaaSvc.RADIUSSessions()
		originator = &radiusserver.Originator{Entropy: rand.Reader, Metrics: obs.Rec}
	}
	reg, err := loadRegistry(operations.Deps{
		Build:          operations.BuildMeta{Version: version, Commit: commit, BuildTime: buildTime, UIVersion: uiVersion},
		State:          mgr,
		Sessions:       authSvc,
		Usage:          authSvc,
		Events:         ring,
		Secrets:        lookup,
		Creds:          creds,
		AAA:            aaaSvc,
		Runtime:        listeners,
		OnRuntimeReset: onReset,
		RADIUSSessions: sessIdx,
		Originator:     originator,
		LoadBaseline: func() (*config.Document, error) {
			next, err := config.Load(configPath)
			if err != nil {
				return nil, err
			}
			if err := config.Validate(next); err != nil {
				return nil, err
			}
			return next, nil
		},
	})
	if err != nil {
		return nil, nil, err
	}
	ready := func() bool {
		if mgr.Snapshot() == nil {
			return false
		}
		if listeners != nil && listeners.Len() > 0 && !listeners.Ready() {
			return false
		}
		if doc.Server.AdminOnly {
			return true
		}
		return listeners != nil && listeners.HasReadyAAA()
	}
	restSrv := &rest.Server{
		Registry:     reg,
		Snapshot:     mgr.Snapshot,
		Auth:         authSvc,
		Events:       ring,
		Ready:        ready,
		MaxBody:      doc.Listeners.HTTP.MaxRequestBodyBytes,
		WriteTimeout: doc.Listeners.HTTP.WriteTimeout,
		IdleTimeout:  doc.Listeners.HTTP.IdleTimeout,
		Logger:       logger,
		Metrics:      obs.Rec,
		Tracer:       obs.Tr,
	}
	mux := http.NewServeMux()
	if admin := obs.AdminMetricsHandler(); admin != nil {
		path := doc.Observability.Metrics.Path
		if path == "" {
			path = "/metrics"
		}
		mux.Handle(path, admin)
	}
	mcpStop := make(chan struct{})
	mcpH := mcpapi.Handler(mcpapi.Options{
		Registry:     reg,
		Snapshot:     mgr.Snapshot,
		Auth:         authSvc,
		Events:       ring,
		MCP:          doc.API.MCP,
		Version:      version,
		WriteTimeout: doc.Listeners.HTTP.WriteTimeout,
		IdleTimeout:  doc.Listeners.HTTP.IdleTimeout,
		MaxBody:      doc.Listeners.HTTP.MaxRequestBodyBytes,
		Metrics:      obs.Rec,
		Tracer:       obs.Tr,
		Done:         mcpStop,
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
	hs.RegisterOnShutdown(func() { close(mcpStop) })
	return hs, ln, nil
}

func loadRegistry(deps operations.Deps) (*operations.Registry, error) {
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

func newRADIUSSessionIndex(doc *config.Document, rec *observability.Recorder) (*radiusruntime.SessionIndex, error) {
	entries := config.DefaultSessionIndexEntries
	bytes := config.DefaultSessionIndexBytes
	ttl := config.DefaultSessionTTL
	if doc != nil {
		acct := doc.Listeners.RADIUSAccounting
		if acct.SessionIndexEntries > 0 {
			entries = acct.SessionIndexEntries
		}
		if acct.SessionIndexBytes > 0 {
			bytes = acct.SessionIndexBytes
		}
		if acct.SessionTTL > 0 {
			ttl = acct.SessionTTL
		}
	}
	return radiusruntime.NewSessionIndex(radiusruntime.Options{
		MaxEntries: entries,
		MaxBytes:   bytes,
		TTL:        ttl,
		Entropy:    rand.Reader,
		Metrics:    rec,
	})
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
		case credentials.RADIUSSharedSecret:
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

func emitLifecycleWarnings(rec *observability.Recorder, snap *state.Snapshot) {
	if rec == nil || snap == nil {
		return
	}
	for _, w := range snap.SecretWarnings() {
		rec.SecretWarning(warningStatus(w.Code))
	}
}

func warningStatus(code domain.Code) string {
	switch code {
	case domain.CodeSharedSecretRotationOverdue:
		return observability.StatusOverdue
	case domain.CodeSharedSecretPolicyViolation:
		return observability.StatusReuse
	default:
		return observability.StatusUnknown
	}
}
