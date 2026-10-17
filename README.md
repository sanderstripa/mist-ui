<p align="center"><img src="icon.svg" width="96" height="96" alt="Mist portal and road logo"></p>
<h1 align="center">Mist UI</h1>
<p align="center">A lightweight control panel for your MIST VPN server.</p>

Mist UI manages **MIST — Multiprotocol Internet Secure Transport** on a Linux VPS. Create separate access keys for your devices, share connection links and QR codes, and manage the server from a compact web interface.

## Features

- Per-device keys with names, expiry dates, access switches, and permanent deletion.
- Personal `mist://` links, QR codes, and JSON profiles for [Connect](https://github.com/sanderstripa/connect).
- Simultaneous clients over HTTP/3 lanes, CONNECT-IP over HTTP/3, and HTTP/2 over TLS.
- Device connection status, upload, download, total traffic, and last activity.
- Live VPS CPU, memory, disk, network throughput, traffic totals, and uptime.
- MIST start, stop, restart, logs, port and DNS settings, and administrator password changes.
- Paired panel and core updates with checksums, configuration checks, backups, and executable rollback on startup failure.
- English and Russian interfaces, light and dark themes, and bundled Montserrat typography.

## Quick install

Run on **Debian or Ubuntu**, using an **amd64 or arm64** VPS:

~~~bash
sudo bash -c 'bash <(curl -fsSL https://raw.githubusercontent.com/sanderstripa/mist-ui/main/install.sh)'
~~~

The installer downloads the latest stable release, verifies SHA-256, installs the panel and compatible MIST core, and sets up automatic TLS certificate renewal. A trusted IPv4 certificate can be issued without a domain. Choose your public IPv4 address, panel port, administrator username, and password during installation.

When installation finishes, it prints the HTTPS panel URL and login details.

| Port | Purpose |
| --- | --- |
| TCP/UDP 443 | Default MIST transport port |
| TCP 2097 | Default HTTPS administration port |
| TCP 80 | IPv4 certificate issuance and renewal |

Allow these ports in your provider's firewall. The installer refuses occupied ports instead of stopping another application. It does not change Xray, 3xUI, or Sudoku services.

### Adopt an existing MIST server

An existing IPv4 configuration at `/etc/mist/server.json` can be adopted when its `authority` matches the VPS IP and its tunnel uses a `/24` subnet. The installer backs up the configuration and preserves the existing static device token and address, so the working client link remains valid. The MIST core briefly restarts.

Configurations using HMAC `token_secret` or an internal IPv6 tunnel require a separate migration. The installer does not silently rotate existing keys or disable an existing IPv6 tunnel.

## Connect a device

1. Open the HTTPS panel URL printed by the installer and sign in.
2. Select **New key**, enter the device name, and choose an expiry period.
3. Copy the connection link or download the JSON profile.
4. In Connect, choose **Add**, paste the link, and connect.
5. Create a separate key for each additional device.

Use the **Access** switch to temporarily block a device. **Delete** permanently revokes its key and removes it from the list. Active connections are checked against the policy and are normally closed within a second of revocation or expiry.

A key supports **one simultaneous connection**. Different keys can connect simultaneously through the same server port. Deleted device addresses remain reserved to prevent an old stream from reaching another device.

Changing the server port briefly restarts MIST and requires updating previously imported profiles. DNS changes apply to newly exported links; existing profiles must be reimported.

## Update

Click **Mist UI v…** in the header, then **Check**. If a newer stable release is available, select **Update**. The panel and core update together, briefly interrupting VPN connections. Keys, credentials, and settings are preserved. Sign in again after the restart and refresh with **Ctrl+F5** if needed.

You can also rerun the quick-install command to update an existing installation, including versions without the in-panel updater. Backups are stored in `/var/backups/mist-ui/`.

Update logs:

~~~bash
journalctl -u 'mist-ui-update-*'
~~~

## Server administration

Service logs:

~~~bash
journalctl -u mist-ui -u mist-edge
~~~

Services: `mist-ui`, `mist-edge`, and the `mist-cert-renew.timer` certificate renewal timer.

To reset the administrator password, run as root:

~~~bash
read -rs -p 'New password: ' MIST_NEW_PASSWORD; echo
printf '%s' "$MIST_NEW_PASSWORD" | /usr/local/bin/mist-ui --reset-password
unset MIST_NEW_PASSWORD
systemctl restart mist-ui
~~~

## Traffic and network scope

Device traffic is measured by the MIST core and accumulated in the protected `usage.json` file across restarts. Traffic from before accounting was enabled cannot be reconstructed. Last activity is recorded by the core. **Active IPs** counts the device's active IPv4 tunnel address: zero or one, rather than a list of public source IPs.

The bottom status bar shows operating-system metrics. VPS traffic totals come from network interface counters; device traffic comes from MIST counters. Hover over the status bar to see the hostname and CPU model.

The panel manages **one MIST Edge** with an IPv4 `/24` subnet and up to 253 device addresses. Generated profiles block IPv6. The bundled core routes tunnel replies to each device's assigned IPv4 address, isolates HTTP/3 lane sessions, validates packet sources, and closes revoked or expired sessions without restarting other clients. Per-device addresses are exported through `fallback_client_cidr` for Connect compatibility.

Xray and the system proxy are not MIST transports. Automated tests do not guarantee performance or connectivity on every network.

## Security

Administration uses HTTPS, bcrypt password hashing, login rate limiting, CSRF protection, and Secure/HttpOnly/SameSite cookies. Keys and state are kept in root-only files. The random panel URL supplements authentication; it does not replace it. Connection links and QR codes contain private access keys and should only be shared with their intended device owner.

## Build and verify

Use **Go 1.27.2** on Linux. The panel embeds its HTML, CSS, JavaScript, fonts, and icons in a Go executable; a production installation needs neither Node.js nor an external web server.

~~~bash
mkdir -p dist
go test -race ./...
go build -o dist/mist-ui .
cd engine
go test -race ./...
go build -o ../dist/mist-edge ./cmd/mist-edge
~~~

CI also tests real simultaneous MIST clients across the three supported transports, plus active revocation of one device while another remains connected. Ready-to-install Linux packages are published in [Releases](https://github.com/sanderstripa/mist-ui/releases).

## Credits and licenses

The interface and authentication structure were adapted from [Sudoku UI](https://github.com/sanderstripa/sudoku-ui); its MIT notice is retained in [LICENSE](LICENSE). The bundled MIST source is based on commit `d4e7dacf22f9c3f4c5d762883544c102da0c6b49`, with a Connect adapter and additional multi-client panel integration.

Montserrat is distributed under the [SIL Open Font License](web/OFL.txt). Go dependencies retain their respective licenses. The repository logo uses the same portal-and-road mark as the panel.
