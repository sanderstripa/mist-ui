# MIST MVP architecture

MIST is an experimental remote-access IP tunnel built from standard Internet protocols rather than a new wire format.

```text
Windows / Linux applications
        |
       TUN
        |
   mist-client
        |
 CONNECT-IP (RFC 9484)
        |
 HTTP Datagrams (RFC 9297)
        |
      HTTP/3
        |
       QUIC
        |
      TLS 1.3
        |
     UDP/443
        |
    mist-edge
        |
       TUN
        |
 routing + NAT
        |
     Internet
```

The edge also serves an ordinary HTTPS page on TCP/443. The MIST CONNECT-IP endpoint is only exposed over the HTTP/3 listener and requires a bearer token.

## Deliberately absent from v0.1

There is no MIST magic number, custom packet header, custom cipher, custom key exchange, fake TLS implementation, packet-size obfuscation, cover traffic, or proprietary handshake.

## Current prototype constraints

- IPv4 full-tunnel only.
- One active client per edge process.
- HTTP/3 + QUIC is the only tunnel transport; HTTP/2 fallback is not implemented yet.
- The client has an ECH configuration hook, but automated ECH server provisioning/discovery is not implemented yet.
- The bearer token is static in the prototype. Production must use short-lived credentials.
- A persistent kill switch is not implemented yet. The client pins the edge route and installs split-default routes while connected, but a production WFP/nftables policy is still required.
- Server firewall/NAT lifecycle is intentionally simple and should be hardened before production use.

This code is a protocol prototype, not an anonymity guarantee and not yet a production VPN service.
