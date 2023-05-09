# tor-fetcher

Like curl, but for fetching .onion URLs that require "haproxy-protection"/"BasedFlare" PoW completion before access is granted.

Uses Golang's argon2 library instead of running the Javascript/WebAssembly bundle.
