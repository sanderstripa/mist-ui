# MIST

MIST is an experimental full-tunnel VPN transport centered on standards-based web transports. Its normal transport order is:

`Fast HTTP/3 lanes -> CONNECT-IP (RFC 9484) over HTTP/3 -> HTTP/2 over TLS 1.3`

The `mist-hardening-32` branch implements the engineering checklist in [`docs/IMPLEMENTATION_32.md`](docs/IMPLEMENTATION_32.md). Implementation is not the same thing as production validation: a release candidate still has to pass the field and soak gates in [`docs/TEST_MATRIX.md`](docs/TEST_MATRIX.md).

## Current client behavior

### Windows

- Native Wintun TUN interface.
- IPv4 full tunnel using two half-default routes.
- Every startup-known Edge IPv4 gets an explicit physical-interface bypass route, so fail-closed reconnects can still reach alternate Edges.
- IPv6 defaults to fail-closed blocking; an optional end-to-end IPv6 tunnel mode is available.
- Classic DNS leak guard: physical adapter DNS is backed up, pointed to loopback while MIST is active, and protected with outbound TCP/UDP 53 firewall rules.
- `-recover` restores MIST network changes after an abnormal exit.
- `kill_switch=fail_closed|fail_open`.
- Reconnect uses bounded exponential backoff with jitter.
- Multiple Edge endpoints / IPs, endpoint health cooldown, provider/ASN diversity preference, and optional signed endpoint discovery.

### Linux client

The same core transport and packet policy compile on Linux, with Linux route / DNS / IPv6 platform handling.

## Transports

### Fast: HTTP/3 lanes

Fast uses one HTTP/3 / QUIC connection with four long-lived authenticated lanes. Inner flows are deterministically sharded across lanes. Receive and Edge lane queues are bounded so a congested lane cannot build unbounded application bufferbloat.

Force it with:

```powershell
.\mist-client-windows-amd64.exe -config .\client.json -transport h3s
```

### Standard: CONNECT-IP / HTTP/3

The standards-based transport uses CONNECT-IP (RFC 9484) over HTTP/3 and supports route/address assignment, including the optional IPv6 assignment.

```powershell
.\mist-client-windows-amd64.exe -config .\client.json -transport h3
```

### Fallback: HTTP/2 / TCP 443

When `h2_fallback=true`, MIST can carry framed IP packets over a bidirectional HTTP/2 request/response on TLS 1.3 TCP/443.

```powershell
.\mist-client-windows-amd64.exe -config .\client.json -transport h2
```

### Extreme external REALITY adapter

MIST does not embed or impersonate REALITY. If `reality_fallback_socks5` is configured, an H2 direct-path failure — including TCP, TLS or ALPN failure — can be retried through a local no-auth SOCKS5 listener owned by an external REALITY-capable core such as Xray or sing-box.

## Dataplane hardening

- Default inner MTU: 1280.
- QUIC DPLPMTUD enabled by default.
- TCP SYN MSS clamping.
- `inner_quic_policy=auto|block|allow`.
- Packet batching on the Fast receive path.
- Bounded lane queues and short buffered stream flushes.
- Local JSON telemetry for traffic, drops, reconnects, failures, endpoint/transport and quality.
- QUIC qlog support via the standard `QLOGDIR` environment variable.

MIST currently uses upstream `quic-go`'s native congestion controller. Brutal is not enabled, and the branch does not expose a fake BBR selector. See the congestion-control item in `docs/IMPLEMENTATION_32.md`.

## Edge hardening

- Linux TUN, forwarding and optional NAT.
- HTTP/3 and HTTPS cover behavior on the same public service identity.
- Configurable real static decoy root.
- Wrong/missing MIST credentials are handled as ordinary web traffic rather than a MIST-specific 401/403 oracle.
- Optional short-lived HMAC bearer tokens (`mist-token`).
- Invalid-probe rate limiting.
- Adaptive QUIC Retry source-address validation after excessive fresh handshakes from one source.
- QUIC stream and HTTP header bounds.
- Optional experimental TCP+UDP alternate public ports using NAT REDIRECT (`port_hop_ports`).

## Endpoint resilience

A logical endpoint may contain several `dial_addresses`, and a client may contain several endpoints. Optional metadata:

```json
{
  "provider": "provider-a",
  "asn": "AS64500"
}
```

After a failure, MIST applies per-endpoint cooldown and prefers a healthy candidate from a different provider / ASN before a correlated candidate when that metadata is available.

Signed discovery is optional. `mist-endpoints` signs a bounded-expiry endpoint manifest with Ed25519. The client verifies signature, version, expiry and endpoint structure before use. Dial addresses are IPv4 literals by design so all Edge bypass routes can be installed before fail-closed full-tunnel routing is active.

## TLS / ECH / wire image

- TLS 1.3 minimum.
- Real HTTP/3 / QUIC, not a custom cleartext handshake.
- Optional ECH client config and Edge ECH keys.
- `mist-echgen` generates ECH deployment material.
- `wire_profile=native` is intentionally the only profile in this branch: MIST does not spoof only a browser ClientHello while emitting a contradictory QUIC wire image.

See [`docs/WIRE_IMAGE.md`](docs/WIRE_IMAGE.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

## Normal Windows usage

Run from an elevated terminal:

```powershell
.\mist-client-windows-amd64.exe -config .\client.json -transport auto
```

Recovery after an abnormal crash:

```powershell
.\mist-client-windows-amd64.exe -recover
```

Verify the live client network state:

```powershell
.\verify-client.ps1 -InterfaceName MIST -ServerIPs 203.0.113.10,198.51.100.20 -ExpectedMTU 1280 -IPv6Mode block -ExpectedDNS 1.1.1.1,1.0.0.1
```

Collect a redacted debug bundle:

```powershell
.\collect-debug.ps1 -Config .\client.json
```

## Edge verification

```bash
sudo bash scripts/verify-edge.sh /etc/mist/server.json
```

The verifier checks TUN/MTU, forwarding, listeners, optional IPv6 state, public decoy behavior, wrong-token behavior and configured port-hop REDIRECT rules.

## Acceptance testing

CI covers unit tests, Linux builds, Windows cross-builds and the vendored Wintun checksum. Field acceptance is stricter than CI and includes:

- each transport independently;
- 60-minute and 8-hour soak runs;
- large downloads/uploads with integrity checks;
- browsers, WebRTC, Git, streaming and DNS-heavy workloads;
- loss / RTT shaping;
- MTU / PMTU cases;
- endpoint failover;
- fail-closed / fail-open behavior;
- DNS and IPv6 leak checks;
- active probing / abuse controls;
- token lifecycle;
- NAT rebinding / network handover behavior.

See [`docs/TEST_MATRIX.md`](docs/TEST_MATRIX.md).

## Explicit current limitations

- The current Edge data plane is still a one-active-client architecture with a fixed client assignment; multi-tenant address allocation is not part of this 32-point hardening batch.
- MIST does not hide the Edge IP and does not promise anonymity against global traffic correlation.
- If every configured Edge/provider/ASN is blocked, software cannot invent a reachable route.
- ECH only provides its intended property when the surrounding public-name, DNS, certificate and key deployment is configured correctly.
- Full preservation of every inner TCP connection across a destroyed outer QUIC session is not claimed; MIST keeps the fail-closed network state and reconnects the outer tunnel.
- Mobile clients and an external security audit remain separate workstreams.
