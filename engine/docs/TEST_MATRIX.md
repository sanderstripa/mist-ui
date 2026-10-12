# MIST acceptance / soak matrix

A speed-test number is **not** an acceptance criterion. MIST is accepted only when real workloads survive the matrix below without route/DNS leaks or unexplained stalls.

## Gate A — automated build/tests

Run from repository root:

```bash
go mod tidy
git diff --exit-code -- go.mod go.sum
go test ./...
go build ./cmd/mist-client
go build ./cmd/mist-edge
go build ./cmd/mist-token
```

Windows cross-build:

```bash
GOOS=windows GOARCH=amd64 go build ./cmd/mist-client
```

Expected: all commands exit 0.

## Gate B — client network state

Windows, elevated PowerShell while MIST is connected:

```powershell
.\scripts\verify-client.ps1 -InterfaceName MIST -ServerIP <EDGE_IPV4> -ExpectedMTU 1280 -IPv6Mode block -ExpectedDNS 1.1.1.1,1.0.0.1
```

Expected: zero FAIL lines. This checks TUN state, MTU, full-tunnel routes, endpoint bypass route, DNS guard and IPv6 fail-closed policy.

## Gate C — edge network state / camouflage

On the Linux edge:

```bash
sudo bash scripts/verify-edge.sh /etc/mist/server.json
```

Expected: zero FAIL lines. A warning for absent NAT is acceptable only if `enable_nat=false` intentionally.

Additional manual active-probe checks:

```bash
curl -kI https://<authority>/
curl -k -X POST -H 'Authorization: Bearer wrong' https://<authority><mist-path> -i
```

Expected: the public site / ordinary HTTP behavior. Wrong credentials must not produce a MIST-specific `401`, `403`, banner, version or error body.

## Gate D — transports

Test each transport independently before `auto`:

```powershell
.\mist-client-windows-amd64.exe -config .\client.json -transport h3s
.\mist-client-windows-amd64.exe -config .\client.json -transport h3
.\mist-client-windows-amd64.exe -config .\client.json -transport h2
```

For every mode verify:
- DNS works;
- ordinary web browsing works;
- at least one 100 MB download completes;
- at least one 100 MB upload completes (use a controlled endpoint);
- no direct-route / DNS / IPv6 leak occurs.

Then test `-transport auto` and confirm logs show the expected preference order.

## Gate E — repeated real traffic

```powershell
.\scripts\soak-client.ps1 -DurationMinutes 60
```

Minimum pre-release gate: 60 minutes with zero failed iterations.

Extended gate:

```powershell
.\scripts\soak-client.ps1 -DurationMinutes 480
```

Target: 8 hours, zero tunnel crashes and >=99.9% successful iterations. Any failure must be correlated with the local `MIST telemetry:` log.

## Gate F — large transfers

Using a controlled HTTP server:
- download >=10 GiB;
- upload >=5 GiB;
- hash the file before/after;
- record wall time and failures.

Target: no corrupted data and no manual reconnect.

## Gate G — workload diversity

Run for at least 30 minutes each:
- many small HTTPS requests;
- HTTP/2 site;
- browser with HTTP/3 enabled and `inner_quic_policy=allow`;
- browser with `inner_quic_policy=auto` (expected inner QUIC Initial drops / browser TCP fallback);
- WebSocket connection;
- WebRTC/video call;
- Git clone/fetch of a large repository;
- streaming video;
- DNS-heavy browsing;
- UDP application where available.

Record whether a workload is TCP, UDP or mixed.

## Gate H — loss / latency shaping

On a lab Linux path, use `tc netem` (or an equivalent controlled WAN emulator) to test:

| RTT | Loss | Expected |
|---:|---:|---|
| 20 ms | 0% | stable |
| 80 ms | 0% | stable |
| 200 ms | 0% | stable |
| 80 ms | 1% | stable, lower throughput acceptable |
| 80 ms | 3% | no deadlock; graceful degradation |
| 200 ms | 1% | no deadlock; graceful degradation |

Do not use this on an unmanaged production host without understanding the shaping rules.

## Gate I — MTU / DPLPMTUD

1. Keep inner MTU at 1280 and verify Gate E.
2. Set a deliberately constrained outer path in a lab and repeat.
3. `pmtu_mode=auto` must remain connected and adapt.
4. `pmtu_mode=off` is a negative-control test and may perform worse.

A PMTU test passes when traffic does not enter a black-hole stall.

## Gate J — endpoint failover

Configure two edges from different providers / ASNs.

1. Start on endpoint A.
2. Block endpoint A at the client firewall or stop edge A.
3. Keep the MIST process running.
4. Verify fail-closed routes remain installed.
5. Verify the client reconnect loop eventually selects B.
6. Verify DNS and HTTPS resume.

Expected telemetry: `dial_failures` and `reconnects` increase; `endpoint` changes to B.

## Gate K — kill switch

### fail_closed

1. Connect MIST.
2. Stop the edge or block both TCP/UDP 443 to all configured endpoints.
3. Try direct HTTPS and DNS.

Expected: no direct Internet escape while the client is retrying.

### fail_open

Repeat with `kill_switch=fail_open`.

Expected: client exits, deferred cleanup removes MIST routes/DNS guards, normal direct network returns.

## Gate L — IPv6

### `ipv6_mode=block`

On a dual-stack access network:
- IPv4 through MIST works;
- native IPv6 cannot bypass MIST;
- `verify-client.ps1` reports both IPv6 blackhole halves.

### `ipv6_mode=tunnel`

Configure matching edge/client IPv6 prefixes and run:

```powershell
.\scripts\verify-client.ps1 -IPv6Mode tunnel
```

Then verify IPv6 egress address belongs to the edge network, not the local ISP.

## Gate M — DNS leak

While MIST is active:
- `verify-client.ps1` must show physical DNS guards;
- resolve at least 100 unique names;
- packet-capture the physical interface and confirm no client-originated plaintext UDP/TCP port 53 leaves it;
- repeat after reconnect/failover.

Applications using DoH are encrypted application traffic and are not counted as plaintext DNS leakage.

## Gate N — active probing / abuse controls

From a test host:
- request random paths without auth;
- request the real MIST path with a wrong token;
- exceed `auth_rate_limit_per_minute`;
- create more fresh QUIC handshakes than `quic_retry_threshold_per_minute`.

Expected:
- no VPN-specific error oracle;
- invalid HTTP requests become decoy/404 behavior;
- excessive QUIC handshakes receive Retry address validation;
- edge remains responsive.

## Gate O — token lifecycle

```bash
export MIST_TOKEN_SECRET='<same secret as server>'
./mist-token-linux-amd64 -client test-device -ttl 15m
```

Expected:
- fresh token connects;
- modified token fails as ordinary decoy traffic;
- token fails after expiration;
- old static tokens work only when the server explicitly retains `token`.

## Gate P — handover / NAT rebinding

Test Wi-Fi -> another network / NAT rebinding while keeping the process alive.

QUIC may transparently survive NAT rebinding. If the outer connection dies completely, MIST must keep fail-closed routes and reconnect. Current acceptance does **not** require existing inner TCP streams to survive a full outer-connection loss; applications may need to reconnect.

## Release threshold

Do not call a build stable based only on FAST/Speedtest. A candidate is release-worthy only when:
- CI is green;
- Gates B–O pass in the intended deployment;
- 8-hour soak passes;
- no DNS/IPv6/direct-route leak is observed;
- failover behavior is repeatable;
- real browser uploads/downloads no longer reproduce the previous multi-minute stalls.
