# MIST hardening roadmap

`mist-hardening-32` is the implementation branch for the canonical checklist in `docs/IMPLEMENTATION_32.md`. The roadmap below now reflects the code that is actually present; field validation remains separate from implementation.

## P0 — dataplane correctness

Implemented:

- bounded Fast receive and per-lane Edge queues;
- conservative MTU 1280;
- QUIC DPLPMTUD by default;
- TCP MSS clamping;
- inner-QUIC policy (`auto`, `block`, `allow`);
- deterministic four-lane Fast scheduler;
- bounded backpressure / drop-on-full rather than unbounded buffering;
- IPv4 full-tunnel routing;
- IPv6 fail-closed by default and optional IPv6 tunnel mode;
- Windows DNS guard and recovery;
- serial reconnect with exponential backoff + jitter;
- fail-closed / fail-open kill-switch policies.

Congestion-control policy is intentionally **native upstream quic-go**. Brutal is not enabled. Upstream `quic-go v0.62` does not expose a safe public pluggable BBR selector through the HTTP/3 + CONNECT-IP stack used here, so MIST does not expose a fake BBR setting.

## P1 — observability and acceptance

Implemented:

- local JSON telemetry;
- endpoint / transport identity;
- TX/RX counters and activity age;
- policy-drop, reconnect, dial-failure, fallback and bridge-error counters;
- quality score;
- qlog tracing for Fast H3, Standard CONNECT-IP and Edge QUIC via `QLOGDIR`;
- sanitized Windows debug bundle;
- client/Edge verification scripts;
- 60-minute and 8-hour soak harness;
- acceptance matrix for large transfers, browser/WebRTC/Git/video/DNS workloads, loss/RTT shaping, MTU, failover and leaks.

Operational validation is still required on the intended Windows machines, VPSes and filtered networks.

## P2 — camouflage and active probing

Implemented:

- ordinary public decoy content on HTTPS and HTTP/3;
- no MIST-specific authentication oracle for invalid credentials;
- short-lived signed bearer tokens plus optional explicit legacy static token;
- invalid-probe rate limiting;
- adaptive QUIC Retry source-address validation;
- HTTP header and QUIC stream caps.

## P3 — transport resilience

Implemented automatic order:

`Fast H3 lanes -> Standard CONNECT-IP/H3 -> H2/TCP`.

Also implemented:

- multiple dial addresses per logical endpoint;
- endpoint health/cooldown;
- provider/ASN diversity preference after failures;
- serial endpoint failover while fail-closed routes remain active.

## P4 — TLS + QUIC wire image

Implemented:

- TLS 1.3 minimum;
- one internally consistent `native` TLS/QUIC profile;
- no partial browser ClientHello impersonation;
- optional ECH client/server support and ECH generator;
- stable normal-mode UDP/443 behavior.

See `docs/WIRE_IMAGE.md`.

## P5 — infrastructure resilience

Implemented:

- multiple endpoints and multiple addresses per endpoint;
- explicit physical-interface bypass route for every startup-known Edge IPv4;
- provider and ASN metadata;
- health-aware ordering and cooldown;
- optional Ed25519-signed HTTPS endpoint discovery with bounded expiry;
- `mist-endpoints` manifest-signing utility.

Deployment still needs genuinely independent providers / ASNs. Software cannot create independent failure domains if all configured servers live inside the same blocked network.

## P6 — extreme escape paths

Implemented as opt-in mechanisms:

- external REALITY-capable SOCKS5 fallback for H2 when direct TCP to the Edge fails;
- experimental Linux TCP+UDP port-hopping front doors using NAT REDIRECT, with matching alternate client `dial_addresses`.

Neither mechanism changes the normal Fast wire image. REALITY remains owned by the external core rather than being partially reimplemented inside MIST.

## Release definition

Implementation completion is not the same as production readiness. A build becomes a stable candidate only after the gates in `docs/TEST_MATRIX.md` pass in the intended deployment, including:

- green CI;
- no IPv4/IPv6/DNS direct leak;
- repeatable failover;
- real browser upload/download stability;
- loss/RTT/MTU tests;
- active-probe tests;
- 8-hour soak.
