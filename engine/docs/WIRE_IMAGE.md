# MIST wire-image policy

MIST deliberately treats the externally observable connection as a single **TLS + QUIC wire image**, not as a TLS fingerprint in isolation.

## Current profile: `native`

`wire_profile=native` is the only supported profile in this hardening branch.

The goal is consistency: MIST uses the native Go TLS 1.3 and quic-go HTTP/3 stack and does **not** claim to be Chrome, Firefox, Safari, Edge or another browser while emitting a different QUIC implementation's transport parameters and behavior.

Observable dimensions include, among other things:

- TLS ClientHello structure and extension ordering;
- ALPN;
- QUIC version negotiation;
- QUIC transport parameters and their ordering/values;
- Initial packet size and padding;
- Connection-ID behavior;
- ACK / PTO / retry behavior;
- stream and datagram usage;
- keepalive and idle timeouts;
- reconnect cadence;
- packet-size / timing statistics.

Changing only ClientHello to a browser preset while leaving the rest of the QUIC behavior native would create a contradictory, potentially rarer fingerprint. MIST therefore does not use that strategy.

## Stable transport choices

The hardening branch fixes several externally relevant choices:

- TLS 1.3 minimum;
- real HTTP/3 / QUIC on the UDP path;
- HTTP/2 over TLS for TCP fallback;
- QUIC Initial packet size 1200;
- one QUIC connection multiplexing Fast lanes;
- no normal-mode port hopping;
- serialized reconnect with exponential backoff and jitter;
- optional ECH when a valid ECH configuration is deployed end-to-end.

## Profile evolution

Future profiles, if added, must be complete and tested as a whole wire image. A profile is not accepted merely because its TLS JA3/JA4-like signature resembles a browser.

A future profile update mechanism must satisfy all of the following before it can be enabled:

1. versioned profile identifiers;
2. signed profile metadata;
3. client compatibility bounds;
4. reproducible packet-capture tests;
5. rollback to `native`;
6. no automatic fingerprint rotation during one failed reconnect sequence.

Until those requirements exist, `native` is intentionally the only accepted value. This is a defensive design choice, not an unfinished browser-spoofing feature.
