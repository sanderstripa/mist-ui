//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type hostSampler struct {
	total, idle, rx, tx uint64
	at                  time.Time
}

func number(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }
func (h *hostSampler) sample() map[string]any {
	out := map[string]any{"available": true}
	b, e := os.ReadFile("/proc/stat")
	if e != nil {
		return map[string]any{"available": false}
	}
	fields := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	var total, idle uint64
	for i := 1; i < len(fields) && i <= 8; i++ {
		total += number(fields[i])
		if i == 4 || i == 5 {
			idle += number(fields[i])
		}
	}
	if h.total > 0 && total > h.total {
		out["cpu"] = 100 * (1 - float64(idle-h.idle)/float64(total-h.total))
	}
	h.total, h.idle = total, idle
	b, _ = os.ReadFile("/proc/meminfo")
	var mem, available uint64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 1 {
			switch f[0] {
			case "MemTotal:":
				mem = number(f[1]) * 1024
			case "MemAvailable:":
				available = number(f[1]) * 1024
			}
		}
	}
	out["ram_total"], out["ram_used"] = mem, mem-available
	var disk syscall.Statfs_t
	if syscall.Statfs("/", &disk) == nil {
		out["disk_total"] = disk.Blocks * uint64(disk.Bsize)
		out["disk_used"] = (disk.Blocks - disk.Bavail) * uint64(disk.Bsize)
	}
	b, _ = os.ReadFile("/proc/net/dev")
	var rx, tx uint64
	for _, line := range strings.Split(string(b), "\n") {
		name, values, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" {
			continue
		}
		if _, err := os.Stat("/sys/class/net/" + name + "/device"); err != nil { // VPS virtual NICs have no device symlink; exclude tunnels and bridges.
			if strings.HasPrefix(name, "mist") || strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") {
				continue
			}
		}
		f := strings.Fields(values)
		if len(f) >= 9 {
			rx += number(f[0])
			tx += number(f[8])
		}
	}
	now := time.Now()
	if !h.at.IsZero() && rx >= h.rx && tx >= h.tx {
		seconds := now.Sub(h.at).Seconds()
		out["rx_rate"] = float64(rx-h.rx) / seconds
		out["tx_rate"] = float64(tx-h.tx) / seconds
	}
	h.rx, h.tx, h.at = rx, tx, now
	out["rx"], out["tx"] = rx, tx
	b, _ = os.ReadFile("/proc/uptime")
	f := strings.Fields(string(b))
	if len(f) > 0 {
		n, _ := strconv.ParseFloat(f[0], 64)
		out["uptime"] = n
	}
	b, _ = os.ReadFile("/proc/cpuinfo")
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "model name") {
			_, model, _ := strings.Cut(line, ":")
			out["model"] = strings.TrimSpace(model)
			break
		}
	}
	name, _ := os.Hostname()
	out["hostname"] = name
	return out
}
