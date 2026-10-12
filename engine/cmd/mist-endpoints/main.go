package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type envelope struct {
	PayloadBase64   string `json:"payload_base64"`
	SignatureBase64 string `json:"signature_base64"`
}

func main() {
	genKey := flag.Bool("gen-key", false, "generate an Ed25519 keypair and exit")
	privateKeyB64 := flag.String("private-key-base64", "", "Ed25519 private key (base64)")
	payloadPath := flag.String("payload", "", "path to raw endpoint payload JSON")
	outPath := flag.String("out", "", "output envelope path (stdout when empty)")
	flag.Parse()

	if *genKey {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil { fatal(err) }
		fmt.Printf("public_key_base64=%s\nprivate_key_base64=%s\n", base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv))
		return
	}
	if *privateKeyB64 == "" || *payloadPath == "" { fatal(fmt.Errorf("-private-key-base64 and -payload are required unless -gen-key is used")) }
	priv, err := base64.StdEncoding.DecodeString(*privateKeyB64)
	if err != nil || len(priv) != ed25519.PrivateKeySize { fatal(fmt.Errorf("private key must be base64-encoded %d-byte Ed25519 private key", ed25519.PrivateKeySize)) }
	payload, err := os.ReadFile(*payloadPath)
	if err != nil { fatal(err) }
	// Validate that the bytes are JSON but sign the exact bytes, not a re-encoding.
	var raw json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil { fatal(fmt.Errorf("payload JSON: %w", err)) }
	sig := ed25519.Sign(ed25519.PrivateKey(priv), payload)
	env := envelope{PayloadBase64: base64.StdEncoding.EncodeToString(payload), SignatureBase64: base64.StdEncoding.EncodeToString(sig)}
	encoded, err := json.MarshalIndent(env, "", "  ")
	if err != nil { fatal(err) }
	encoded = append(encoded, '\n')
	if *outPath == "" { _, _ = os.Stdout.Write(encoded); return }
	if err := os.WriteFile(*outPath, encoded, 0600); err != nil { fatal(err) }
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "mist-endpoints:", err)
	os.Exit(2)
}
