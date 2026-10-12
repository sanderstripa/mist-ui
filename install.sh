#!/usr/bin/env bash
set -Eeuo pipefail
REPO=sanderstripa/mist-ui
die(){ echo "Ошибка: $*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die 'Запустите установщик от root (sudo bash).'
[[ -r /etc/os-release ]] || die 'Нужен Debian или Ubuntu.'
. /etc/os-release
[[ $ID == debian || $ID == ubuntu ]] || die 'Поддерживаются Debian и Ubuntu.'
case $(uname -m) in x86_64) ARCH=amd64;;aarch64) ARCH=arm64;;*) die 'Поддерживаются amd64 и arm64.';;esac
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
echo 'MIST UI — установка панели и совместимого MIST Edge'
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl jq tar openssl iproute2 iptables qrencode python3-venv
work=$(mktemp -d /tmp/mist-ui-install.XXXXXX)
trap 'rm -rf "$work"' EXIT
curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" -o "$work/release.json" || die 'Стабильный выпуск ещё недоступен. Проверьте страницу Releases.'
url=$(jq -r --arg name "mist-ui-linux-$ARCH.tar.gz" '.assets[]|select(.name==$name)|.browser_download_url' "$work/release.json")
shaurl=$(jq -r '.assets[]|select(.name=="SHA256SUMS")|.browser_download_url' "$work/release.json")
[[ -n $url && -n $shaurl ]] || die 'В выпуске отсутствует пакет для вашей архитектуры.'
curl -fL "$url" -o "$work/mist-ui-linux-$ARCH.tar.gz"
curl -fL "$shaurl" -o "$work/SHA256SUMS"
(cd "$work"; grep "  mist-ui-linux-$ARCH.tar.gz$" SHA256SUMS | sha256sum -c -) || die 'Контрольная сумма пакета не совпала.'
tar -xzf "$work/mist-ui-linux-$ARCH.tar.gz" -C "$work"
for file in mist-ui mist-edge; do [[ -x $work/$file ]] || die "Нет файла $file"; done
upgrading=0
[[ -f /etc/mist-ui/config.json ]] && upgrading=1
if [[ $upgrading == 0 ]]; then
 ip=$(curl -4fsSL https://api.ipify.org)
 read -r -p "IPv4 адрес VPS [$ip]: " answer </dev/tty; ip=${answer:-$ip}
 python3 -c 'import ipaddress,sys; ip=ipaddress.ip_address(sys.argv[1]); assert ip.version==4 and ip.is_global' "$ip" || die 'Укажите публичный IPv4.'
 read -r -p 'Порт HTTPS-панели [2097]: ' panel_port </dev/tty; panel_port=${panel_port:-2097}
 [[ $panel_port =~ ^[0-9]+$ ]] && ((panel_port>0&&panel_port<65536)) || die 'Некорректный порт.'
 [[ $panel_port != 80 ]] || die 'TCP 80 зарезервирован для выдачи и продления сертификата.'
 ss -H -lnt "sport = :$panel_port" | grep -q . && die 'Порт панели занят. Выберите свободный порт.'
 read -r -p 'Логин администратора [admin]: ' username </dev/tty; username=${username:-admin}
 read -r -s -p 'Пароль (12–72 символа; Enter — сгенерировать): ' password </dev/tty;echo
 password=${password:-$(openssl rand -hex 16)}
 (( ${#password}>=12 && ${#password}<=72 )) || die 'Пароль должен содержать 12–72 символа.'
fi
stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup=/var/backups/mist-ui/$stamp
install -d -m 700 "$backup"
managed=(/opt/mist/mist-edge /usr/local/bin/mist-ui /etc/mist/server.json /etc/mist-ui/config.json /etc/mist-ui/state.json /etc/systemd/system/mist-edge.service /etc/systemd/system/mist-ui.service /etc/systemd/system/mist-cert-renew.service /etc/systemd/system/mist-cert-renew.timer /usr/local/sbin/mist-cert-deploy)
for path in "${managed[@]}"; do if [[ -f $path ]]; then mkdir -p "$backup$(dirname "$path")"; cp -p "$path" "$backup$path"; fi; done
old_core_active=$(systemctl is-active mist-edge.service 2>/dev/null || true)
old_panel_active=$(systemctl is-active mist-ui.service 2>/dev/null || true)
rollback(){
 trap - ERR
 echo "Установка не завершена. Восстанавливаю файлы из $backup" >&2
 systemctl stop mist-ui.service mist-edge.service 2>/dev/null || true
 for path in "${managed[@]}"; do
  if [[ -f $backup$path ]]; then mkdir -p "$(dirname "$path")"; cp -p "$backup$path" "$path"
  elif [[ -f $path ]]; then rm -f "$path"; fi
 done
 systemctl daemon-reload
 [[ $old_core_active == active ]] && systemctl start mist-edge.service || true
 [[ $old_panel_active == active ]] && systemctl start mist-ui.service || true
 echo 'Xray и Sudoku не изменялись. Резервная копия сохранена.' >&2
 exit 1
}
trap rollback ERR
install -d -m 700 /etc/mist /etc/mist-ui /var/lib/mist-ui
if [[ ! -f /etc/mist/server.json ]]; then
 read -r -p 'Порт MIST TCP/UDP [443]: ' vpn_port </dev/tty;vpn_port=${vpn_port:-443}
 [[ $vpn_port =~ ^[0-9]+$ ]] && ((vpn_port>0&&vpn_port<65536)) || die 'Некорректный порт MIST.'
 [[ $vpn_port != 80 ]] || die 'TCP 80 зарезервирован для сертификата.'
 [[ $vpn_port != "$panel_port" ]] || die 'Порты панели и MIST должны различаться.'
 if ss -H -lnt "sport = :$vpn_port" | grep -q . || ss -H -lnu "sport = :$vpn_port" | grep -q .; then die 'Порт MIST занят. Существующую службу установщик не остановит.'; fi
 if ss -H -lnt 'sport = :80' | grep -q .; then die 'Для выдачи IP-сертификата нужен свободный TCP 80. Существующий веб-сервер не остановлен.'; fi
 if ip -4 route show table all | grep -qE '(^|[[:space:]])10\.77\.43\.'; then die 'Подсеть 10.77.43.0/24 занята; настройте другую MIST-подсеть заранее.'; fi
 python3 -m venv /opt/mist-certbot
 /opt/mist-certbot/bin/pip install --disable-pip-version-check 'certbot>=5.4'
 /opt/mist-certbot/bin/certbot certonly --standalone --preferred-profile shortlived --ip-address "$ip" --cert-name mist-ip --non-interactive --agree-tos --register-unsafely-without-email --config-dir /etc/mist/acme --work-dir /var/lib/mist-acme --logs-dir /var/log/mist-acme
 python3 - "$ip" "$vpn_port" <<'PY'
import json,secrets,sys,pathlib
cfg={'listen':':'+sys.argv[2],'authority':sys.argv[1],'path':'/assets/'+secrets.token_hex(12),'certificate':'/etc/mist/acme/live/mist-ip/fullchain.pem','private_key':'/etc/mist/acme/live/mist-ip/privkey.pem','tun_name':'mist0','tun_cidr':'10.77.43.1/24','client_cidr':'10.77.43.2/32','advertise_cidr':'0.0.0.0/0','mtu':1280,'enable_nat':True,'wire_profile':'native','port_hop_ports':[]}
p=pathlib.Path('/etc/mist/server.json');p.write_text(json.dumps(cfg,indent=2));p.chmod(0o600)
PY
fi
if [[ $upgrading == 0 ]]; then
 authority=$(jq -r '.authority // empty' /etc/mist/server.json)
 jq -e '(.tun_ipv6_cidr // "") == "" and (.client_ipv6_cidr // "") == ""' /etc/mist/server.json >/dev/null || die 'Эта версия панели управляет IPv4. Существующий IPv6-туннель не изменён; требуется отдельная миграция.'
 [[ $authority == "$ip" ]] || die 'IPv4 панели должен совпадать с authority существующего MIST.'
 cert=$(jq -r '.certificate' /etc/mist/server.json);key=$(jq -r '.private_key' /etc/mist/server.json)
 legacy_key=$(jq -r '.token // empty' /etc/mist/server.json)
 openssl x509 -in "$cert" -checkip "$ip" -noout || die 'Сертификат MIST не подходит для IP панели.'
 openssl x509 -in "$cert" -checkend 3600 -noout || die 'Сначала продлите TLS-сертификат MIST.'
 printf '%s' "$password" | "$work/mist-ui" --init --username "$username" --listen ":$panel_port" --cert "$cert" --key "$key"
fi
install -d -m 755 /opt/mist
install -m 755 "$work/mist-edge" /opt/mist/mist-edge
install -m 755 "$work/mist-ui" /usr/local/bin/mist-ui
cat >/etc/systemd/system/mist-edge.service <<'UNIT'
[Unit]
Description=MIST Edge managed by MIST UI
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=/opt/mist/mist-edge --config /etc/mist/server.json
Restart=on-failure
RestartSec=3
UMask=0077
LimitNOFILE=65536
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
cat >/etc/systemd/system/mist-ui.service <<'UNIT'
[Unit]
Description=MIST UI
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/mist-ui
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
cat >/usr/local/sbin/mist-cert-deploy <<'HOOK'
#!/bin/sh
set -eu
systemctl try-restart mist-edge.service mist-ui.service
HOOK
chmod 700 /usr/local/sbin/mist-cert-deploy
if [[ -x /opt/mist-certbot/bin/certbot && -d /etc/mist/acme/renewal ]]; then
 cat >/etc/systemd/system/mist-cert-renew.service <<'UNIT'
[Unit]
Description=Renew MIST IP certificate
[Service]
Type=oneshot
ExecStart=/opt/mist-certbot/bin/certbot renew --config-dir /etc/mist/acme --work-dir /var/lib/mist-acme --logs-dir /var/log/mist-acme --deploy-hook /usr/local/sbin/mist-cert-deploy
UNIT
 cat >/etc/systemd/system/mist-cert-renew.timer <<'UNIT'
[Unit]
Description=Automatic renewal of MIST TLS certificate
[Timer]
OnCalendar=*-*-* 00,06,12,18:00:00
RandomizedDelaySec=300
Persistent=true
[Install]
WantedBy=timers.target
UNIT
 systemctl daemon-reload
 systemctl enable --now mist-cert-renew.timer
fi
/opt/mist/mist-edge --check-config --config /etc/mist/server.json
systemctl daemon-reload
systemctl enable mist-edge.service mist-ui.service
systemctl restart mist-edge.service mist-ui.service
sleep 3
systemctl is-active --quiet mist-edge.service
systemctl is-active --quiet mist-ui.service
trap - ERR
if [[ $upgrading == 0 ]]; then
 webpath=$(jq -r '.web_path' /etc/mist-ui/config.json)
 printf '\nMIST UI установлена.\nПанель: https://%s:%s%s/\nЛогин: %s\nПароль: %s\n' "$ip" "$panel_port" "$webpath" "$username" "$password"
 [[ -z ${legacy_key:-} ]] || printf 'Существующий ключ сохранён как «Существующее устройство».\n'
else echo 'MIST UI обновлена. Ключи и пароль сохранены.';fi
echo "Резервная копия: $backup"
echo 'Откройте TCP-порт панели и TCP/UDP-порт MIST в firewall вашего провайдера. TCP 80 нужен для автоматического продления сертификата.'
