package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type releaseAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}
type releaseInfo struct {
	Tag    string         `json:"tag_name"`
	Assets []releaseAsset `json:"assets"`
}

var releaseClient = &http.Client{Timeout: 30 * time.Second}

func latestRelease(ctx context.Context) (releaseInfo, error) {
	var out releaseInfo
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/repos/sanderstripa/mist-ui/releases/latest", nil)
	req.Header.Set("User-Agent", "MIST-UI/"+Version)
	r, e := releaseClient.Do(req)
	if e != nil {
		return out, e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return out, fmt.Errorf("GitHub: %d", r.StatusCode)
	}
	e = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&out)
	return out, e
}
func (a *App) checkUpdate(w http.ResponseWriter, r *http.Request) {
	release, e := latestRelease(r.Context())
	if e != nil {
		problem(w, 502, "Не удалось проверить GitHub Releases")
		return
	}
	response(w, 200, map[string]any{"current": Version, "latest": strings.TrimPrefix(release.Tag, "v"), "available": newer(release.Tag, Version)})
}
func newer(tag, current string) bool {
	var a, b [3]int
	fmt.Sscanf(strings.TrimPrefix(tag, "v"), "%d.%d.%d", &a[0], &a[1], &a[2])
	fmt.Sscanf(strings.TrimPrefix(current, "v"), "%d.%d.%d", &b[0], &b[1], &b[2])
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}
func safeReleaseURL(url, tag string) bool {
	return strings.HasPrefix(url, "https://github.com/sanderstripa/mist-ui/releases/download/"+tag+"/") && !strings.Contains(tag, "/")
}
func download(ctx context.Context, url string, max int64) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return nil, e
	}
	r, e := releaseClient.Do(req)
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("download: %d", r.StatusCode)
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, max+1))
	if int64(len(b)) > max {
		return nil, fmt.Errorf("package too large")
	}
	return b, e
}
func unpackPair(data []byte, dir string) error {
	gz, e := gzip.NewReader(bytes.NewReader(data))
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		entry, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if entry.Name != "mist-ui" && entry.Name != "mist-edge" {
			continue
		}
		if entry.Typeflag != tar.TypeReg || entry.Size > 64<<20 || seen[entry.Name] {
			return fmt.Errorf("invalid executable entry")
		}
		seen[entry.Name] = true
		f, e := os.OpenFile(filepath.Join(dir, entry.Name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
		if e != nil {
			return e
		}
		_, e = io.Copy(f, tr)
		f.Close()
		if e != nil {
			return e
		}
	}
	if !seen["mist-ui"] || !seen["mist-edge"] {
		return fmt.Errorf("incomplete package")
	}
	return nil
}
func (a *App) startUpdate(w http.ResponseWriter, r *http.Request) {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		problem(w, 409, "Обновление поддерживается на Linux amd64/arm64")
		return
	}
	a.mu.Lock()
	if a.updating {
		a.mu.Unlock()
		problem(w, 409, "Обновление уже выполняется")
		return
	}
	a.updating = true
	a.mu.Unlock()
	started := false
	defer func() {
		if !started {
			a.mu.Lock()
			a.updating = false
			a.mu.Unlock()
		}
	}()
	rel, e := latestRelease(r.Context())
	if e != nil {
		problem(w, 502, "GitHub недоступен")
		return
	}
	if !newer(rel.Tag, Version) {
		response(w, 200, map[string]bool{"updating": false})
		return
	}
	name := "mist-ui-linux-" + runtime.GOARCH + ".tar.gz"
	urls := map[string]string{}
	for _, asset := range rel.Assets {
		if safeReleaseURL(asset.URL, rel.Tag) {
			urls[asset.Name] = asset.URL
		}
	}
	if urls[name] == "" || urls["SHA256SUMS"] == "" {
		problem(w, 502, "Выпуск неполный")
		return
	}
	data, e := download(r.Context(), urls[name], 32<<20)
	if e != nil {
		problem(w, 502, "Не удалось скачать пакет")
		return
	}
	sums, e := download(r.Context(), urls["SHA256SUMS"], 64<<10)
	if e != nil {
		problem(w, 502, "Нет контрольных сумм")
		return
	}
	sum := sha256.Sum256(data)
	valid := false
	for _, line := range strings.Split(string(sums), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[1] == name && f[0] == hex.EncodeToString(sum[:]) {
			valid = true
		}
	}
	if !valid {
		problem(w, 502, "Контрольная сумма не совпала")
		return
	}
	dir, e := os.MkdirTemp("/var/lib/mist-ui", "update-")
	if e != nil {
		problem(w, 500, "Не удалось подготовить обновление")
		return
	}
	defer func() {
		if !started {
			os.RemoveAll(dir)
		}
	}()
	if e = unpackPair(data, dir); e != nil {
		problem(w, 502, "Некорректный пакет")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if e = exec.CommandContext(ctx, filepath.Join(dir, "mist-edge"), "--check-config", "--config", a.cfg.ServerFile).Run(); e != nil {
		problem(w, 409, "Новое ядро отклонило конфигурацию; текущая версия сохранена")
		return
	}
	// A separate systemd unit survives the panel restart. Only the fixed MIST pair is replaced.
	script := `#!/bin/bash
set -Eeuo pipefail
work="$1"
backup="/var/backups/mist-ui/update-$(date -u +%Y%m%dT%H%M%S)-$$"
mkdir -p "$backup"
chmod 700 "$backup"
cp -p /usr/local/bin/mist-ui "$backup/mist-ui"
cp -p /opt/mist/mist-edge "$backup/mist-edge"
core_active=$(systemctl is-active mist-edge.service || true)
rollback(){
 trap - ERR
 cp -p "$backup/mist-ui" /usr/local/bin/mist-ui.new
 cp -p "$backup/mist-edge" /opt/mist/mist-edge.new
 mv -f /usr/local/bin/mist-ui.new /usr/local/bin/mist-ui
 mv -f /opt/mist/mist-edge.new /opt/mist/mist-edge
 [[ $core_active != active ]] || systemctl restart mist-edge.service
 systemctl restart mist-ui.service
 exit 1
}
trap rollback ERR
install -m 755 "$work/mist-ui" /usr/local/bin/mist-ui.new
install -m 755 "$work/mist-edge" /opt/mist/mist-edge.new
mv -f /usr/local/bin/mist-ui.new /usr/local/bin/mist-ui
mv -f /opt/mist/mist-edge.new /opt/mist/mist-edge
[[ $core_active != active ]] || systemctl restart mist-edge.service
systemctl restart mist-ui.service
sleep 4
systemctl is-active --quiet mist-ui.service
[[ $core_active != active ]] || systemctl is-active --quiet mist-edge.service
rm -rf "$work"
`
	scriptPath := filepath.Join(dir, "apply.sh")
	if os.WriteFile(scriptPath, []byte(script), 0700) != nil {
		problem(w, 500, "Не удалось подготовить обновление")
		return
	}
	cmd := exec.Command("systemd-run", "--unit=mist-ui-update-"+random(6), "--on-active=2s", "/bin/bash", scriptPath, dir)
	if e = cmd.Run(); e != nil {
		problem(w, 500, "Не удалось запустить обновление; текущая версия сохранена")
		return
	}
	started = true
	response(w, 202, map[string]bool{"updating": true})
}
