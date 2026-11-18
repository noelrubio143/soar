// soar-client: a tiny standalone client for the Soar DNS tunnel (github.com/getlantern/soar).
//
// Soar ships a client *library* and a server, but no client executable. This wrapper gives
// AMBERV2RAY the same shape as libvaydns.so / libslipstream.so: a static binary that listens on
// a local TCP port and forwards every connection through the DNS tunnel to a fixed destination
// that the Soar server dials on our behalf (typically 127.0.0.1:22 for SSH).
//
// Build (see .github/workflows/build-soar.yml):
//   CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o libsoar.so .
//
// Server side the destination must be allowed, e.g. for SSH on the same VPS:
//   soar-server -zone t.example.com -key-file key -listen :53 -allow-private -allow-ports 22
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/getlantern/soar"
)

func main() {
	var (
		zone      = flag.String("zone", "", "tunnel zone delegated to the Soar server, e.g. t.example.com")
		pubkey    = flag.String("pubkey", "", "server Ed25519 public key (hex, base64 or base64url; from `soar-server pubkey`)")
		resolvers = flag.String("resolvers", "", "comma-separated resolvers (ip, ip:port, [ipv6]:port); all are used at once")
		listen    = flag.String("listen", "127.0.0.1:2227", "local TCP address to listen on")
		target    = flag.String("target", "127.0.0.1:22", "destination the Soar server should dial (host:port)")
		tcpMode   = flag.String("tcp", "auto", "TCP/53 paths: auto | on | only | off")
		discovery = flag.Bool("discovery", false, "let Soar discover more working resolvers")
		country   = flag.String("country", "", "country code for discovery lists, e.g. IR (optional)")
		logLevel  = flag.String("log-level", "info", "debug | info | warn | error")
		dialTO    = flag.Duration("dial-timeout", 30*time.Second, "timeout for opening one tunnel stream")
	)
	flag.Parse()

	logger := newLogger(*logLevel)

	if strings.TrimSpace(*zone) == "" {
		fatal("-zone is required")
	}
	key, err := parseKey(*pubkey)
	if err != nil {
		fatal("bad -pubkey: " + err.Error())
	}
	var rs []string
	for _, r := range strings.Split(*resolvers, ",") {
		if r = normalizeResolver(r); r != "" {
			rs = append(rs, r)
		}
	}
	if len(rs) == 0 && !*discovery {
		fatal("give at least one -resolvers entry, or enable -discovery")
	}
	switch *tcpMode {
	case "auto", "on", "only", "off":
	default:
		fatal("-tcp must be auto, on, only or off")
	}

	cfg := soar.Config{
		Zone:      strings.TrimSpace(*zone),
		ServerKey: key,
		Resolvers: rs,
		TCP:       *tcpMode,
		Logger:    logger,
	}
	if *discovery {
		cfg.Discovery = soar.Discovery{Enabled: true, Country: strings.ToUpper(strings.TrimSpace(*country))}
	}

	client, err := soar.NewClient(cfg)
	if err != nil {
		fatal("soar: " + err.Error())
	}
	defer client.Close()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fatal("listen: " + err.Error())
	}
	defer ln.Close()

	logger.Info("soar-client ready", "listen", ln.Addr().String(), "zone", cfg.Zone,
		"resolvers", len(rs), "target", *target, "tcp", *tcpMode, "discovery", *discovery)
	fmt.Printf("READY listening on %s, tunnelling to %s\n", ln.Addr(), *target)

	// Warm-up: Soar handshakes lazily on the first stream, so do it now and log the outcome.
	// The listener is already up, so the app can connect meanwhile.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), *dialTO)
		defer cancel()
		t0 := time.Now()
		c, err := client.DialContext(ctx, "tcp", *target)
		if err != nil {
			logger.Warn("warm-up failed (check zone, pubkey, resolvers, server -allow-* flags)", "err", err)
			return
		}
		c.Close()
		logger.Info("tunnel up", "handshake", time.Since(t0).Round(time.Millisecond).String())
	}()

	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Warn("accept", "err", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go serve(client, conn, *target, *dialTO, logger)
	}
}

// serve pipes one local connection through a fresh tunnel stream to target.
func serve(client *soar.Client, local net.Conn, target string, timeout time.Duration, logger *slog.Logger) {
	defer local.Close()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	up, err := client.DialContext(ctx, "tcp", target)
	cancel()
	if err != nil {
		logger.Warn("dial through tunnel failed", "err", err)
		return
	}
	defer up.Close()

	var once sync.Once
	done := make(chan struct{})
	finish := func() { once.Do(func() { close(done) }) }

	go func() { io.Copy(up, local); finish() }()
	go func() { io.Copy(local, up); finish() }()
	<-done
}

func parseKey(s string) (ed25519.PublicKey, error) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return nil, errors.New("empty")
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
	}
	return nil, fmt.Errorf("expected a %d-byte Ed25519 key in hex or base64", ed25519.PublicKeySize)
}

// normalizeResolver turns "1.1.1.1", "[::1]" or bare IPv6 into host:port (default port 53).
func normalizeResolver(r string) string {
	r = strings.TrimSpace(r)
	if r == "" {
		return ""
	}
	if strings.HasPrefix(r, "[") {
		if strings.Contains(r, "]:") {
			return r
		}
		return strings.TrimSuffix(r, "]") + "]:53"
	}
	if strings.Count(r, ":") >= 2 { // bare IPv6
		return "[" + r + "]:53"
	}
	if strings.Contains(r, ":") {
		return r
	}
	return r + ":53"
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv}))
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "soar-client:", msg)
	os.Exit(2)
}
