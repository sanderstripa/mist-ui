# MIST — canonical 32-point hardening checklist

This file freezes the implementation scope of the `mist-hardening-32` branch so the code and the acceptance tests use the same numbered checklist.

Status vocabulary:
- **DONE** — implemented in code/config/scripts and covered by CI or a deterministic verifier where possible.
- **DONE / field gate** — implementation is present, but the claim that it works on a particular ISP/VPS/network still requires the deployment test listed below.
- **POLICY DONE** — the engineering decision is implemented explicitly; the branch does not claim a feature the current dependency cannot safely provide.

## P0 — dataplane correctness and stability

### 1. Bounded TUN / transport queues — DONE
Fast receive uses bounded channels and the Edge uses bounded per-lane queues. A congested lane is not allowed to grow an unbounded application queue.

Verify: `go test ./...`, then watch memory during `scripts/soak-client.ps1`; memory must not grow monotonically with a stalled consumer.

### 2. Conservative inner MTU — DONE
Client and Edge default to MTU 1280, with config validation limited to 1200–1500.

Verify: `verify-client.ps1 -ExpectedMTU 1280` and `verify-edge.sh`.

### 3. QUIC DPLPMTUD — DONE
QUIC Path MTU Discovery is enabled by default; `pmtu_mode=off` exists only as a diagnostic negative control.

Verify: Gate I in `TEST_MATRIX.md` on a constrained lab path.

### 4. TCP MSS clamping — DONE
The packet policy rewrites TCP SYN MSS to the configured safe ceiling and updates checksums.

Verify: `go test ./internal/packetpolicy` and packet capture of an inner TCP SYN.

### 5. Inner QUIC policy — DONE
`inner_quic_policy=auto|block|allow` is applied before packets enter the outer tunnel. `auto` suppresses inner QUIC Initial traffic so browsers can fall back to TCP instead of creating QUIC-in-QUIC pathologies.

Verify: packet-policy unit tests plus Gate G with browser HTTP/3.

### 6. Fast lane scheduler — DONE
Fast traffic is deterministically sharded across four long-lived HTTP/3 lanes using flow hashing, keeping one flow on one lane while distributing independent flows.

Verify: `-transport h3s`, simultaneous downloads, and Edge lane logs 0–3.

### 7. Backpressure / bufferbloat control — DONE
Edge lane queues are bounded and non-blocking; queue overflow drops a packet instead of stalling the Edge TUN reader. Stream writes are buffered with a short flush interval.

Verify: loss/RTT shaping in Gate H and memory/latency observation during soak.

### 8. Congestion-control policy — POLICY DONE
The production branch uses upstream `quic-go`'s native congestion controller. Brutal is not enabled. The public `quic-go v0.62` API used by the CONNECT-IP stack does not expose a safe pluggable BBR selector, so the branch explicitly does not fake a BBR setting that would have no effect.

Verify: `go.mod` contains upstream `github.com/quic-go/quic-go v0.62.0`; no Brutal/BBR pseudo-setting is accepted by MIST config.

### 9. IPv4 full-tunnel routing — DONE
The client installs two half-default routes through MIST while pinning every Edge IPv4 outside the TUN; Edge forwarding/NAT is configured on Linux.

Verify: `verify-client.ps1`, `verify-edge.sh`, and compare public IPv4 before/after connection.

### 10. IPv6 fail-closed + optional tunnel — DONE / field gate
Default mode blocks native IPv6 bypass. Optional `ipv6_mode=tunnel` configures IPv6 on the client/Edge and advertises the IPv6 route through CONNECT-IP.

Verify: Gate L on a genuinely dual-stack access network.

### 11. DNS leak guard and crash recovery — DONE / field gate
Windows backs up physical-adapter DNS, points physical adapters at loopback while connected, installs outbound port-53 guards, restores DNS on cleanup, and provides `-recover` after an abnormal exit.

Verify: `verify-client.ps1`, Gate M packet capture, then kill the process and run `mist-client ... -recover`.

### 12. Reconnect with exponential backoff + jitter — DONE
Reconnect waits 1/2/4/8/15 seconds (capped), adds jitter, and retries endpoint candidates serially rather than producing a parallel handshake burst.

Verify: unit tests plus stop the active Edge during Gate J.

### 13. Kill switch — DONE / field gate
`fail_closed` keeps full-tunnel routes active while reconnecting. `fail_open` exits and deferred cleanup restores the direct network.

Verify: both branches in Gate K.

## P1 — observability and acceptance

### 14. Local structured telemetry — DONE
Periodic JSON telemetry includes TX/RX packets/bytes, policy drops, inner-QUIC/IPv6 drops, reconnects, dial failures, transport fallbacks, bridge errors, active endpoint/transport, dial latency, activity age and a quality score.

Verify: run the client for >`telemetry_interval_seconds` and inspect `MIST telemetry:` lines.

### 15. QUIC qlog — DONE
Fast HTTP/3, Standard CONNECT-IP and Edge QUIC configs use `qlog.DefaultConnectionTracer`. qlog is opt-in through the standard `QLOGDIR` environment variable.

Verify: create a writable `QLOGDIR`, connect with `h3s` and `h3`, then confirm `.sqlog` files are produced.

### 16. Sanitized Windows debug bundle — DONE
`collect-debug.ps1` captures adapters, routes, DNS, firewall state, network events and MIST process state while redacting MIST token/ECH fields from the copied config.

Verify: run the script, unzip the result, inspect `client-config-redacted.json` before sharing.

### 17. Soak + real-workload acceptance matrix — DONE / field gate
Repository includes deterministic verification scripts, a repeatable JSONL soak harness, large-transfer requirements, browser/WebRTC/Git/video/DNS workloads, netem loss/RTT cases, MTU tests, failover, leak tests and an 8-hour release gate.

Verify: execute Gates A–P in `TEST_MATRIX.md`.

## P2 — camouflage and active probing

### 18. Real public decoy site — DONE
Unknown requests on HTTPS and HTTP/3 are served as an ordinary site/404. `decoy_root` can point to real static cover content.

Verify: open the Edge hostname in a browser and run Gate C.

### 19. No authentication oracle — DONE
Missing/wrong bearer credentials do not return a MIST-specific 401/403/banner. They are sent through ordinary public-site behavior.

Verify: Gate C/N with the real path and an invalid token.

### 20. Short-lived signed tokens — DONE
The Edge accepts HMAC-signed expiring bearer tokens in addition to an explicitly configured legacy static token. `mist-token` generates them.

Verify: Gate O including expiry and tamper tests.

### 21. Abuse controls: rate limit, adaptive QUIC Retry, stream/header caps — DONE / field gate
Invalid public probes are rate-limited. Excess fresh QUIC handshakes from one source trigger QUIC Retry source validation. HTTP headers and incoming QUIC streams are bounded.

Verify: Gate N from a controlled test host.

## P3 — transport resilience

### 22. Fast HTTP/3 lanes — DONE
Fast mode is a single HTTP/3 transport with four long-lived authenticated lanes and bounded lane buffering.

Verify: `mist-client ... -transport h3s`.

### 23. Standard CONNECT-IP over HTTP/3 — DONE
RFC 9484 CONNECT-IP remains the standards-based Standard transport and supports route/address assignment, including optional IPv6.

Verify: `mist-client ... -transport h3`.

### 24. HTTP/2 / TCP 443 fallback — DONE
When enabled, MIST carries framed IP packets over a bidirectional HTTP/2 request/response on TLS 1.3 TCP/443.

Verify: block UDP/443 and run `-transport auto` or force `-transport h2`.

## P4 — wire image

### 25. Consistent TLS + QUIC wire-image policy — DONE
MIST uses one internally consistent `native` profile instead of spoofing only a browser ClientHello while retaining contradictory QUIC parameters. TLS 1.3 is mandatory.

Verify: config rejects unsupported `wire_profile`; see `WIRE_IMAGE.md` and packet capture.

### 26. ECH support — DONE / deployment gate
Client accepts a serialized ECHConfigList; Edge loads ECH server keys; `mist-echgen` generates deployment material.

Verify: ECH unit tests, then a deployment capture proving the intended public-name design actually negotiates ECH.

## P5 — infrastructure resilience

### 27. Multiple addresses / endpoint front doors — DONE
One logical endpoint can expand to multiple `dial_addresses` (for example `:443` plus an emergency redirected port). Every known IPv4 is pinned outside the TUN before fail-closed routing is installed.

Verify: configure two addresses, block the first, confirm the second is attempted and both have bypass routes.

### 28. Provider / ASN diversity preference — DONE
Endpoint metadata supports `provider` and `asn`. After a failure/cooldown, healthy candidates from an independent provider/ASN are preferred before correlated candidates.

Verify: unit test `TestOrderedEndpointsPrefersIndependentFailureDomain` and Gate J with two real providers.

### 29. Endpoint health score and cooldown — DONE
Failures increase exponential per-endpoint cooldown (capped at five minutes); success clears failures/cooldown and records last dial latency/success.

Verify: endpoint-health unit tests and repeated failure logs.

### 30. Signed endpoint discovery — DONE / deployment gate
Optional HTTPS bootstrap returns an Ed25519-signed opaque payload with an expiry and endpoint list. Signature, version, expiry, size and endpoint structure are validated before use; static and discovered candidates are merged/deduplicated. Startup-discovered IPs are included in bypass routing.

Verify: discovery unit tests and a manifest generated by `mist-endpoints`.

## P6 — extreme escape paths

### 31. External REALITY-compatible SOCKS5 fallback — DONE / deployment gate
MIST does not embed or impersonate REALITY. If configured, a failed direct H2 TCP connection can be retried through a local SOCKS5 listener provided by an external REALITY-capable core. The SOCKS5 adapter is covered by a protocol unit test.

Verify: point `reality_fallback_socks5` at a controlled Xray/sing-box SOCKS listener, block direct TCP to the Edge, and force `h2`.

### 32. Experimental port-hopping front doors — DONE / deployment gate
The Linux Edge can install TCP+UDP NAT PREROUTING redirect front doors (`port_hop_ports`) to the primary listener. The client reaches them by listing matching `dial_addresses`. This is an emergency failover mechanism, not periodic hopping inside a healthy QUIC connection.

Verify: configure `port_hop_ports`, confirm iptables REDIRECT rules, block `:443`, and connect to a configured alternate port.

## What this branch deliberately does not claim

- It does **not** claim a custom BBR/Brutal QUIC controller. Upstream quic-go does not expose that hook through the stack MIST currently uses. Switching the entire HTTP/3 + CONNECT-IP stack to a congestion-control fork is a separate dependency migration and must not be represented as already working.
- It does **not** claim anonymity against global traffic correlation, a hidden Edge IP, or guaranteed reachability after every provider/ASN is blocked.
- It does **not** claim that CI proves censorship resistance. Items marked **field gate** require the real tests above.
