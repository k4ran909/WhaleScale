package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/k4ran909/whalescale/internal/config"
	"github.com/k4ran909/whalescale/internal/policy"
	"github.com/k4ran909/whalescale/internal/server"
	"github.com/k4ran909/whalescale/internal/store"
	"github.com/k4ran909/whalescale/internal/stun"
	"github.com/k4ran909/whalescale/internal/version"
	"github.com/k4ran909/whalescale/web"
)

type serveOpts struct {
	db, listen, publicURL, stunListen, dnsSuffix, policyFile string
	certFile, keyFile, metricsListen, logLevel               string
	oidcIssuer, oidcClientID, oidcSecret, oidcSecretFile     string
	oidcAdmins, oidcUsers, oidcDomains                       string
	gatewayDomain, acmeEmail, acmeCache, recordingsDir       string
	policyURL, policyTokenFile, webhookSecretFile            string
	policySyncInterval                                       time.Duration
	relayQUICListen                                          string
	console, tlsACME, flowLogs                               bool
	flowRetention                                            time.Duration
}

var secretSettings = map[string]bool{"oidc-client-secret": true}

func defineServeFlags(fs *flag.FlagSet) *serveOpts {
	o := &serveOpts{}
	fs.String("config", defaultConfigPath(), "config file (YAML, keys are these flag names)")
	fs.StringVar(&o.db, "db", "whalescale.db", "SQLite database path")
	fs.StringVar(&o.listen, "listen", ":8080", "HTTP(S) listen address")
	fs.StringVar(&o.publicURL, "public-url", "", "URL nodes and browsers use to reach this server (default: derived from --listen)")
	fs.StringVar(&o.relayQUICListen, "relay-quic-listen", ":3480", "UDP address for the QUIC relay (faster than the WebSocket relay); empty disables")
	fs.StringVar(&o.stunListen, "stun-listen", ":3478", "comma-separated UDP addresses for STUN; two ports let nodes detect symmetric NAT; empty disables")
	fs.StringVar(&o.dnsSuffix, "dns-suffix", "whale.internal", "MagicDNS domain suffix")
	fs.StringVar(&o.policyFile, "policy", "", "policy file (JSON); without it, the policy is edited in the console")
	fs.StringVar(&o.policyURL, "policy-url", "", "follow the policy at this HTTPS URL, e.g. a Git repository's raw file on a branch")
	fs.StringVar(&o.policyTokenFile, "policy-url-token-file", "", "file with a token sent as 'Authorization: Bearer' when fetching policy-url (private repositories)")
	fs.DurationVar(&o.policySyncInterval, "policy-sync-interval", time.Minute, "how often to check policy-url for changes")
	fs.StringVar(&o.webhookSecretFile, "policy-webhook-secret-file", "", "file with the secret for POST /policy/sync push webhooks (GitHub, Gitea, GitLab)")
	fs.StringVar(&o.certFile, "tls-cert", "", "TLS certificate file (PEM)")
	fs.StringVar(&o.keyFile, "tls-key", "", "TLS private key file (PEM)")
	fs.BoolVar(&o.tlsACME, "tls-acme", false, "get certificates from Let's Encrypt automatically (needs port 443 reachable from the internet)")
	fs.StringVar(&o.acmeEmail, "acme-email", "", "contact email for Let's Encrypt (expiry warnings)")
	fs.StringVar(&o.acmeCache, "acme-cache", "", "directory for ACME certificates (default: 'acme' next to the database)")
	fs.BoolVar(&o.flowLogs, "flow-logs", false, "have nodes report connection activity (who talked to whom, ports, bytes, refused attempts)")
	fs.DurationVar(&o.flowRetention, "flow-log-retention", 7*24*time.Hour, "how long flow logs are kept")
	fs.StringVar(&o.recordingsDir, "recordings-dir", "", "where recorded SSH sessions are stored (default: 'recordings' next to the database)")
	fs.StringVar(&o.gatewayDomain, "gateway-domain", "", "publish machines' services at <name>.<this domain>; needs a wildcard DNS record pointing here")
	fs.StringVar(&o.metricsListen, "metrics-listen", "127.0.0.1:9090", "Prometheus /metrics listen address; empty disables")
	fs.StringVar(&o.logLevel, "log-level", "info", "debug, info, warn or error")
	fs.BoolVar(&o.console, "console", true, "serve the web console")
	fs.StringVar(&o.oidcIssuer, "oidc-issuer", "", "OpenID Connect issuer URL; enables browser login")
	fs.StringVar(&o.oidcClientID, "oidc-client-id", "", "OIDC client ID")
	fs.StringVar(&o.oidcSecret, "oidc-client-secret", "", "OIDC client secret (prefer --oidc-client-secret-file or the env var)")
	fs.StringVar(&o.oidcSecretFile, "oidc-client-secret-file", "", "file containing the OIDC client secret")
	fs.StringVar(&o.oidcAdmins, "oidc-admins", "", "comma-separated emails allowed into the console")
	fs.StringVar(&o.oidcUsers, "oidc-allowed-users", "", "comma-separated emails allowed to add devices (admins always can)")
	fs.StringVar(&o.oidcDomains, "oidc-allowed-domains", "", "comma-separated email domains allowed to add devices")
	return o
}

func loadServeConfig(args []string, quiet bool) (*serveOpts, config.Sources, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	if quiet {
		fs.SetOutput(io.Discard)
	}
	o := defineServeFlags(fs)
	path, explicit := config.ConfigPath(args, defaultConfigPath())
	src, err := config.Load(fs, path, explicit, args)
	if err != nil {
		return nil, nil, err
	}
	return o, src, nil
}

// resolve fills derived values and checks the configuration for mistakes.
func (o *serveOpts) resolve() []error {
	var errs []error
	if (o.certFile == "") != (o.keyFile == "") {
		errs = append(errs, errors.New("tls-cert and tls-key must be set together"))
	}
	if o.tlsACME {
		if o.certFile != "" {
			errs = append(errs, errors.New("use either tls-acme or tls-cert/tls-key, not both"))
		}
		if o.publicURL == "" {
			errs = append(errs, errors.New("tls-acme needs public-url (the name to get a certificate for)"))
		}
		if o.acmeCache == "" {
			o.acmeCache = filepath.Join(filepath.Dir(o.db), "acme")
		}
	}
	if o.policyURL != "" && o.policyFile != "" {
		errs = append(errs, errors.New("use either policy or policy-url, not both"))
	}
	for _, f := range []string{o.policyTokenFile, o.webhookSecretFile} {
		if f != "" {
			if _, err := os.Stat(f); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if o.recordingsDir == "" {
		o.recordingsDir = filepath.Join(filepath.Dir(o.db), "recordings")
	}
	if d := o.gatewayDomain; d != "" && (strings.Contains(d, "/") || strings.Contains(d, ":") || !strings.Contains(strings.Trim(d, "."), ".")) {
		errs = append(errs, fmt.Errorf("gateway-domain %q must be a bare domain like apps.example.com", d))
	}
	for _, f := range []string{o.certFile, o.keyFile, o.policyFile} {
		if f != "" {
			if _, err := os.Stat(f); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if o.publicURL == "" {
		host := o.listen
		if strings.HasPrefix(host, ":") {
			host = "127.0.0.1" + host
		}
		scheme := "http"
		if o.certFile != "" || o.tlsACME {
			scheme = "https"
		}
		o.publicURL = scheme + "://" + host
	}
	if u, err := url.Parse(o.publicURL); err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		errs = append(errs, fmt.Errorf("public-url %q must be an http(s) URL", o.publicURL))
	}
	for _, a := range splitList(o.stunListen) {
		if _, err := net.ResolveUDPAddr("udp", a); err != nil {
			errs = append(errs, fmt.Errorf("stun-listen %q: %w", a, err))
		}
	}
	if o.policyFile != "" {
		if b, err := os.ReadFile(o.policyFile); err == nil {
			if _, err := policy.Parse(b); err != nil {
				errs = append(errs, fmt.Errorf("policy %s: %w", o.policyFile, err))
			}
		}
	}
	if o.oidcSecretFile != "" {
		b, err := os.ReadFile(o.oidcSecretFile)
		if err != nil {
			errs = append(errs, err)
		}
		o.oidcSecret = strings.TrimSpace(string(b))
	}
	if o.oidcIssuer != "" {
		if o.oidcClientID == "" || o.oidcSecret == "" {
			errs = append(errs, errors.New("oidc-issuer needs oidc-client-id and a client secret"))
		}
		if len(splitList(o.oidcAdmins)) == 0 {
			errs = append(errs, errors.New("oidc-issuer needs at least one oidc-admins email"))
		}
		if !strings.HasPrefix(o.publicURL, "https://") && !isLoopbackURL(o.publicURL) {
			errs = append(errs, errors.New("OIDC needs an https public-url (identity providers reject plain-http redirects)"))
		}
	}
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(o.logLevel)); err != nil {
		errs = append(errs, fmt.Errorf("log-level: %w", err))
	}
	return errs
}

func isLoopbackURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return isLoopback(net.JoinHostPort(u.Hostname(), "0"))
}

func (o *serveOpts) oidc() *server.OIDCConfig {
	if o.oidcIssuer == "" {
		return nil
	}
	return &server.OIDCConfig{
		Issuer: o.oidcIssuer, ClientID: o.oidcClientID, ClientSecret: o.oidcSecret,
		Admins: splitList(o.oidcAdmins), AllowedUsers: splitList(o.oidcUsers), AllowedDomains: splitList(o.oidcDomains),
	}
}

func cmdConfigtest(args []string) error {
	o, src, err := loadServeConfig(args, false)
	if err != nil {
		return err
	}
	errs := o.resolve()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	defineServeFlags(fs)
	var names []string
	fs.VisitAll(func(f *flag.Flag) { names = append(names, f.Name) })
	sort.Strings(names)
	vals := map[string]string{
		"db": o.db, "listen": o.listen, "public-url": o.publicURL, "stun-listen": o.stunListen,
		"dns-suffix": o.dnsSuffix, "policy": o.policyFile, "tls-cert": o.certFile, "tls-key": o.keyFile,
		"metrics-listen": o.metricsListen, "log-level": o.logLevel, "console": fmt.Sprint(o.console),
		"oidc-issuer": o.oidcIssuer, "oidc-client-id": o.oidcClientID, "oidc-client-secret": o.oidcSecret,
		"oidc-client-secret-file": o.oidcSecretFile, "oidc-admins": o.oidcAdmins,
		"oidc-allowed-users": o.oidcUsers, "oidc-allowed-domains": o.oidcDomains,
		"gateway-domain": o.gatewayDomain, "tls-acme": fmt.Sprint(o.tlsACME), "acme-email": o.acmeEmail,
		"acme-cache": o.acmeCache, "recordings-dir": o.recordingsDir,
		"flow-logs": fmt.Sprint(o.flowLogs), "flow-log-retention": o.flowRetention.String(),
		"policy-url": o.policyURL, "policy-url-token-file": o.policyTokenFile,
		"policy-sync-interval": o.policySyncInterval.String(), "policy-webhook-secret-file": o.webhookSecretFile,
		"relay-quic-listen": o.relayQUICListen,
	}
	for _, n := range names {
		v, ok := vals[n]
		if !ok {
			continue
		}
		if secretSettings[n] && v != "" {
			v = "<redacted>"
		}
		from := src[n]
		if from == "" {
			from = "default"
		}
		fmt.Printf("%-24s %-40s (%s)\n", n, v, from)
	}
	if len(errs) > 0 {
		fmt.Println()
		for _, e := range errs {
			fmt.Println("✘", e)
		}
		return fmt.Errorf("%d configuration problem(s)", len(errs))
	}
	fmt.Println("\n✔ configuration ok")
	return nil
}

func cmdServe(args []string) error {
	o, _, err := loadServeConfig(args, false)
	if err != nil {
		return err
	}
	if errs := o.resolve(); len(errs) > 0 {
		return errors.Join(errs...)
	}
	var lvl slog.Level
	lvl.UnmarshalText([]byte(o.logLevel))
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

	st, err := store.Open(context.Background(), o.db)
	if err != nil {
		return err
	}
	defer st.Close()

	tlsOn := o.certFile != "" || o.tlsACME
	if !tlsOn && !isLoopback(o.listen) && !strings.HasPrefix(o.publicURL, "https://") {
		log.Warn("serving plain HTTP on a non-loopback address: auth keys and node tokens travel in cleartext. Use --tls-cert/--tls-key or a TLS reverse proxy.")
	}
	pu, _ := url.Parse(o.publicURL)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var stunAdvertise []string
	for _, a := range splitList(o.stunListen) {
		pc, err := net.ListenPacket("udp", a)
		if err != nil {
			return fmt.Errorf("stun listen %s: %w", a, err)
		}
		_, port, _ := net.SplitHostPort(pc.LocalAddr().String())
		stunAdvertise = append(stunAdvertise, net.JoinHostPort(pu.Hostname(), port))
		go func() {
			if err := stun.Serve(ctx, pc, log); err != nil {
				log.Error("stun", "err", err)
			}
		}()
	}

	cfg := server.Config{
		PublicURL: o.publicURL, STUN: stunAdvertise, DNSSuffix: o.dnsSuffix, PolicyFile: o.policyFile,
		OIDC: o.oidc(), GatewayDomain: o.gatewayDomain, RecordingsDir: o.recordingsDir,
		FlowLogs: o.flowLogs, FlowRetention: o.flowRetention, Log: log,
	}
	var quicPC net.PacketConn
	if o.relayQUICListen != "" {
		if quicPC, err = net.ListenPacket("udp", o.relayQUICListen); err != nil {
			return fmt.Errorf("relay-quic-listen %s: %w", o.relayQUICListen, err)
		}
		_, port, _ := net.SplitHostPort(quicPC.LocalAddr().String())
		cfg.RelayQUICAddr = net.JoinHostPort(pu.Hostname(), port)
	}
	if o.policyURL != "" {
		ps := &server.PolicySyncConfig{URL: o.policyURL, Interval: o.policySyncInterval}
		if o.policyTokenFile != "" {
			b, err := os.ReadFile(o.policyTokenFile)
			if err != nil {
				return err
			}
			ps.Token = strings.TrimSpace(string(b))
		}
		if o.webhookSecretFile != "" {
			b, err := os.ReadFile(o.webhookSecretFile)
			if err != nil {
				return err
			}
			ps.WebhookSecret = strings.TrimSpace(string(b))
		}
		cfg.PolicySync = ps
	}
	if o.console {
		cfg.Console = web.Dist()
	}
	srv, err := server.New(st, cfg)
	if err != nil {
		return err
	}
	go srv.Watch(ctx, 5*time.Second)
	if quicPC != nil {
		go func() {
			if err := srv.ServeRelayQUIC(ctx, quicPC); err != nil {
				log.Error("QUIC relay", "err", err)
			}
		}()
	}

	if o.metricsListen != "" {
		mux := http.NewServeMux()
		mux.Handle("GET /metrics", srv.MetricsHandler())
		ms := &http.Server{Addr: o.metricsListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Info("metrics listening", "addr", o.metricsListen)
			if err := ms.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("metrics", "err", err)
			}
		}()
		defer ms.Close()
	}

	hs := &http.Server{
		Addr:              o.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	if o.tlsACME {
		m := &autocert.Manager{
			Prompt: autocert.AcceptTOS, Email: o.acmeEmail, Cache: autocert.DirCache(o.acmeCache),
			// Only our own name and live gateway exposures: strangers can't
			// make us request certificates for arbitrary hosts.
			HostPolicy: srv.AllowTLSHost,
		}
		hs.TLSConfig = m.TLSConfig()
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("whalescale listening", "addr", o.listen, "public_url", o.publicURL, "stun", stunAdvertise, "quic_relay", cfg.RelayQUICAddr,
			"tls", tlsOn, "acme", o.tlsACME, "gateway_domain", o.gatewayDomain, "oidc", o.oidcIssuer != "",
			"db", o.db, "version", version.Version)
		if tlsOn {
			errc <- hs.ListenAndServeTLS(o.certFile, o.keyFile) // empty with ACME: certs come from TLSConfig
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return hs.Shutdown(shutdownCtx)
}
