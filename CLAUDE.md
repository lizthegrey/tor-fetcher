# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
go build              # Build ./tor-fetcher binary
go test ./...         # Run all tests
go test -v -run TestTartarusCheck  # Run a single test
gofmt -w main.go      # Format before committing
```

CI runs on CircleCI with `cimg/go:1.25` (large resource class): `go install ./...` then `go test ./...`.

## What This Tool Does

tor-fetcher is a curl-like CLI for fetching .onion URLs protected by proof-of-work challenges (BasedFlare/haproxy-protection and Tartarus). It solves PoW challenges natively in Go (Argon2 for BasedFlare, SHA256 for Tartarus) instead of running the sites' JavaScript/WebAssembly bundles.

## Architecture

All code lives in a single `main.go` (~460 lines) with tests in `main_test.go`. This is intentional — keep it in one file.

**Module path:** `github.com/endharassment/tor-fetcher`.

### Key Types

- **`TorClient`** — Wraps `http.Client` with cookie jar, manual redirect handling, and custom transport. Entry point is `Fetch()` which loops through challenge-solve-retry cycles (max 10 hops).
- **`utlsTransport`** — Custom `http.RoundTripper` using uTLS Firefox fingerprints for browser-like TLS. Supports HTTP/2 via ALPN with per-host connection caching. Dials through SOCKS5 proxy.
- **`ArgonParams`** — BasedFlare PoW: Argon2id key derivation, nonce must produce hash with N leading zero nibbles.
- **`TartarusParams`** — Tartarus PoW: SHA256-based, nonce must produce hash below `1 << (32 - difficulty)`.

### Challenge Flow

`Fetch()` detects challenges via HTTP 203/403 status codes. It checks for `data-ttrs-challenge` HTML attribute to distinguish Tartarus from BasedFlare, then calls the appropriate solver (`solveTartarus` or `solveBasedFlare`). Solvers brute-force nonces, POST the solution, and the resulting clearance cookie allows the re-GET to succeed.

### Key Dependencies

| Dependency | Purpose |
|-----------|---------|
| `refraction-networking/utls` | Firefox TLS fingerprinting |
| `golang.org/x/crypto` | Argon2id hashing |
| `golang.org/x/net` | HTTP/2 + SOCKS5 proxy dialing |

### CLI Flags

`--target` (required URL), `--proxy` (default `socks5://127.0.0.1:9050`), `--ua` (User-Agent), `--debug` (slog debug to stderr), `-p` (Argon2 parallelism), `-l` (Argon2 key length).

## Testing Notes

Tests use table-driven style. `TestSolveTartarusFlow` is an integration test that spins up an HTTPS test server simulating the challenge-response flow. Tests run fast (~10ms) and don't require a running Tor daemon.
