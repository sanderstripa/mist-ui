package accesspolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"sync"
	"time"
)

type Key struct {
	ID        string `json:"id"`
	TokenHash string `json:"token_hash"`
	Address   string `json:"address"`
	Enabled   bool   `json:"enabled"`
	Revoked   bool   `json:"revoked,omitempty"`
	Expires   int64  `json:"expires,omitempty"`
}
type Policy struct {
	Version int   `json:"version"`
	Keys    []Key `json:"keys"`
}
type Store struct {
	Path  string
	mu    sync.Mutex
	stamp time.Time
	size  int64
	keys  map[string]Key
}

func Hash(token string) string { s := sha256.Sum256([]byte(token)); return hex.EncodeToString(s[:]) }
func (s *Store) Lookup(token string, now time.Time) (Key, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Stat(s.Path)
	if err != nil {
		return Key{}, err
	}
	if s.keys == nil || !info.ModTime().Equal(s.stamp) || info.Size() != s.size {
		b, err := os.ReadFile(s.Path)
		if err != nil {
			return Key{}, err
		}
		var p Policy
		if err = json.Unmarshal(b, &p); err != nil {
			return Key{}, err
		}
		if p.Version != 1 {
			return Key{}, errors.New("unsupported policy")
		}
		keys := map[string]Key{}
		addresses := map[netip.Addr]bool{}
		for _, k := range p.Keys {
			ip, err := netip.ParseAddr(k.Address)
			h, he := hex.DecodeString(k.TokenHash)
			if err != nil || !ip.Is4() || ip.IsUnspecified() || k.ID == "" || he != nil || len(h) != 32 || addresses[ip] {
				return Key{}, errors.New("invalid policy address")
			}
			if _, ok := keys[k.TokenHash]; ok {
				return Key{}, errors.New("duplicate token")
			}
			keys[k.TokenHash] = k
			addresses[ip] = true
		}
		s.keys = keys
		s.stamp = info.ModTime()
		s.size = info.Size()
	}
	k, ok := s.keys[Hash(token)]
	if !ok || !k.Enabled || k.Revoked || (k.Expires != 0 && now.Unix() >= k.Expires) {
		return Key{}, errors.New("access denied")
	}
	return k, nil
}
