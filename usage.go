package main

import "path/filepath"

type Usage struct {
	RX, TX                 uint64
	PreviousRX, PreviousTX uint64
	Epoch                  int64
	LastSeen               int64
}

// Called with the app lock held. Counters are monotonic across core restarts.
func (a *App) accountTraffic(stats map[string]Traffic) map[string]Traffic {
	usage := map[string]Usage{}
	path := filepath.Join(a.dir, "usage.json")
	_ = readJSON(path, &usage)
	if usage == nil {
		usage = map[string]Usage{}
	}
	out := map[string]Traffic{}
	for address, current := range stats {
		prior := usage[address]
		rx, tx := current.RX, current.TX
		if prior.Epoch == current.Epoch {
			if rx >= prior.PreviousRX {
				rx -= prior.PreviousRX
			}
			if tx >= prior.PreviousTX {
				tx -= prior.PreviousTX
			}
		}
		prior.RX += rx
		prior.TX += tx
		prior.PreviousRX = current.RX
		prior.PreviousTX = current.TX
		prior.Epoch = current.Epoch
		if current.LastSeen > prior.LastSeen {
			prior.LastSeen = current.LastSeen
		}
		usage[address] = prior
	}
	_ = writeJSON(path, usage)
	for address, prior := range usage {
		current := stats[address]
		current.RX = prior.RX
		current.TX = prior.TX
		current.LastSeen = prior.LastSeen
		out[address] = current
	}
	return out
}
