# MIST threat model

This document defines what MIST is designed to resist and what it does **not** claim to hide.

## A. Passive protocol classification

Observer capabilities:
- sees client/server IPs, ports, packet sizes, directions and timings;
- can parse cleartext QUIC headers and TLS-visible metadata;
- cannot decrypt TLS 1.3 application data.

MIST controls:
- real TLS 1.3 + HTTP/3 / QUIC rather than a custom cleartext VPN handshake;
- no MIST magic bytes before authentication;
- `wire_profile=native`: do not claim to be Chrome/Firefox while using a different QUIC implementation;
- one long-lived QUIC connection multiplexes Fast lanes;
- ECH can be configured where the surrounding DNS/TLS infrastructure supports it.

Residual risk:
- IP/ASN, long-lived-flow behavior, packet timing and volume remain observable;
- a sufficiently capable classifier can still distinguish unusual HTTP/3 usage statistically.

## B. Active probing

Observer capabilities:
- connects directly to the public server;
- knows or guesses paths and headers;
- sends malformed or incorrect credentials repeatedly.

MIST controls:
- the public endpoint is an ordinary HTTP/3 + HTTPS site by default;
- invalid/missing bearer tokens are served ordinary decoy content / ordinary 404s, not `401 MIST` or another VPN-specific oracle;
- short-lived HMAC bearer tokens are supported;
- invalid public probes are source-rate-limited;
- excessive fresh QUIC handshakes from a source trigger QUIC Retry source-address validation;
- HTTP header and QUIC stream limits bound per-connection resource use.

Residual risk:
- a scanner that possesses valid credentials is an authorized MIST client and can identify the service;
- distributed probing from many real addresses can bypass per-source limits.

## C. Infrastructure blocking

Observer capabilities:
- blocks an IP, prefix or entire ASN/provider without identifying MIST on the wire.

MIST controls:
- client config supports multiple independent endpoints;
- all configured endpoint IPs are explicitly routed outside the TUN;
- endpoints are attempted serially to avoid handshake storms;
- reconnect preserves the TUN / fail-closed routes while rotating through endpoints.

Residual risk:
- if all configured endpoints/providers are blocked, MIST cannot manufacture a reachable network path;
- endpoint discovery/distribution is an operational system outside the current transport binary.

## D. Transport blocking / degradation

Observer capabilities:
- blocks or throttles UDP/443 / QUIC;
- selectively degrades a path.

MIST controls:
- automatic transport order: Fast H3 lanes -> standard CONNECT-IP/H3 -> H2/TCP;
- DPLPMTUD is enabled by default;
- conservative inner MTU starts at 1280;
- sequential reconnect uses exponential backoff with jitter.

Residual risk:
- a network that blocks the destination IP still wins;
- a network that permits TCP/443 but fingerprints the H2 endpoint may still interfere.

## E. Statistical / behavioral classification

Observer capabilities:
- builds models from packet sizes, inter-arrival timing, connection lifetime, throughput and reconnect behavior.

MIST controls:
- no aggressive port hopping in normal Fast mode;
- no browser fingerprint spoofing that produces a contradictory TLS/QUIC wire image;
- reconnects are serialized and jittered;
- Brutal-style fixed-rate traffic is not enabled in the current core.

Residual risk:
- MIST does not currently add cover traffic, padding schedules or timing obfuscation;
- those techniques cost bandwidth/latency and are deliberately excluded until the dataplane is stable.

## F. Local leak / fail-open risk

Threat:
- tunnel fails and traffic silently escapes through the physical interface;
- DNS or IPv6 bypasses the IPv4 tunnel.

MIST controls:
- `kill_switch=fail_closed` by default keeps tunnel routes in place while reconnecting;
- physical plaintext DNS is blocked while MIST is active on Windows;
- IPv6 defaults to `block`; optional end-to-end IPv6 tunnel mode is explicit;
- recovery commands restore local routes/DNS after a clean or manual recovery.

## Explicit non-goals

MIST is not Tor and does not promise sender anonymity against global traffic correlation. It does not hide the VPN server IP. It does not guarantee that an IP/ASN cannot be blocked. It does not claim to be undetectable. The objective is to remove cheap protocol signatures, provide several standards-based transports, and degrade gracefully when one path is impaired.
