package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

var raw = base64.RawURLEncoding

// Mint creates a compact HMAC-authenticated bearer token. The token carries no
// secret material and can be verified statelessly by the edge.
func Mint(secret, clientID string, now time.Time, ttl time.Duration) (string, error) {
	if len(secret) < 16 { return "", errors.New("token secret must be at least 16 bytes") }
	if clientID == "" { return "", errors.New("client id is required") }
	if ttl <= 0 || ttl > 24*time.Hour { return "", errors.New("ttl must be >0 and <=24h") }
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil { return "", err }
	payload := fmt.Sprintf("v1:%s:%d:%d:%s", escape(clientID), now.Unix(), now.Add(ttl).Unix(), raw.EncodeToString(nonce))
	mac := sign(secret, payload)
	return raw.EncodeToString([]byte(payload)) + "." + raw.EncodeToString(mac), nil
}

func Verify(secret, token string, now time.Time) (clientID string, err error) {
	if len(secret) < 16 { return "", errors.New("token secret must be at least 16 bytes") }
	parts := strings.Split(token, ".")
	if len(parts) != 2 { return "", errors.New("invalid token format") }
	payloadBytes, err := raw.DecodeString(parts[0]); if err != nil { return "", errors.New("invalid token payload") }
	mac, err := raw.DecodeString(parts[1]); if err != nil { return "", errors.New("invalid token signature") }
	payload := string(payloadBytes)
	if !hmac.Equal(mac, sign(secret, payload)) { return "", errors.New("invalid token signature") }
	f := strings.Split(payload, ":")
	if len(f) != 5 || f[0] != "v1" { return "", errors.New("invalid token payload") }
	iat, err := strconv.ParseInt(f[2], 10, 64); if err != nil { return "", errors.New("invalid iat") }
	exp, err := strconv.ParseInt(f[3], 10, 64); if err != nil { return "", errors.New("invalid exp") }
	if exp <= iat || exp-iat > int64((24*time.Hour).Seconds()) { return "", errors.New("invalid token lifetime") }
	// 2 minutes of clock skew is tolerated, while future-minted tokens are not.
	if now.Unix()+120 < iat { return "", errors.New("token not yet valid") }
	if now.Unix() >= exp { return "", errors.New("token expired") }
	id := unescape(f[1])
	if id == "" { return "", errors.New("empty client id") }
	return id, nil
}

func sign(secret, payload string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write([]byte(payload))
	return h.Sum(nil)
}

func escape(s string) string { return raw.EncodeToString([]byte(s)) }
func unescape(s string) string { b, _ := raw.DecodeString(s); return string(b) }
