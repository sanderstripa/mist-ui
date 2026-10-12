package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

const (
	echVersion = 0xfe0d
	kemX25519  = 0x0020
	kdfSHA256  = 0x0001
	aeadAES128 = 0x0001
	aeadChaCha = 0x0003
)

type serverKeyJSON struct {
	ConfigBase64     string `json:"config_base64"`
	PrivateKeyBase64 string `json:"private_key_base64"`
	SendAsRetry      bool   `json:"send_as_retry"`
}

type outputJSON struct {
	PublicName              string        `json:"public_name"`
	ConfigID                uint8         `json:"config_id"`
	ServerKey               serverKeyJSON `json:"server_key"`
	ClientECHConfigListBase64 string       `json:"client_ech_config_list_base64"`
	DNSHTTPSRecordECHBase64 string        `json:"dns_https_ech_base64"`
}

func main() {
	publicName := flag.String("public-name", "", "ECH public name (cover/client-facing DNS name)")
	maxNameLength := flag.Int("max-name-length", 0, "maximum backend name length for ECH padding (0-255)")
	flag.Parse()

	if err := validatePublicName(*publicName); err != nil {
		fmt.Fprintln(os.Stderr, "public-name:", err)
		os.Exit(2)
	}
	if *maxNameLength < 0 || *maxNameLength > 255 {
		fmt.Fprintln(os.Stderr, "max-name-length must be between 0 and 255")
		os.Exit(2)
	}

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "generate X25519 key:", err)
		os.Exit(1)
	}
	var id [1]byte
	if _, err := rand.Read(id[:]); err != nil {
		fmt.Fprintln(os.Stderr, "generate config id:", err)
		os.Exit(1)
	}

	config, list, err := buildECHConfig(id[0], privateKey.PublicKey().Bytes(), uint8(*maxNameLength), *publicName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "build ECH config:", err)
		os.Exit(1)
	}

	out := outputJSON{
		PublicName: *publicName,
		ConfigID:   id[0],
		ServerKey: serverKeyJSON{
			ConfigBase64:     base64.StdEncoding.EncodeToString(config),
			PrivateKeyBase64: base64.StdEncoding.EncodeToString(privateKey.Bytes()),
			SendAsRetry:      true,
		},
		ClientECHConfigListBase64: base64.StdEncoding.EncodeToString(list),
		DNSHTTPSRecordECHBase64:   base64.StdEncoding.EncodeToString(list),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "encode output:", err)
		os.Exit(1)
	}
}

func buildECHConfig(configID uint8, publicKey []byte, maximumNameLength uint8, publicName string) ([]byte, []byte, error) {
	if len(publicKey) == 0 || len(publicKey) > 0xffff {
		return nil, nil, errors.New("invalid HPKE public key length")
	}
	if len(publicName) == 0 || len(publicName) > 255 {
		return nil, nil, errors.New("public name must be 1..255 bytes")
	}

	contents := make([]byte, 0, 96)
	contents = append(contents, configID)
	contents = appendU16(contents, kemX25519)
	contents = appendU16(contents, uint16(len(publicKey)))
	contents = append(contents, publicKey...)

	// Two HPKE suites: HKDF-SHA256 with AES-128-GCM and ChaCha20-Poly1305.
	suites := make([]byte, 0, 8)
	suites = appendU16(suites, kdfSHA256)
	suites = appendU16(suites, aeadAES128)
	suites = appendU16(suites, kdfSHA256)
	suites = appendU16(suites, aeadChaCha)
	contents = appendU16(contents, uint16(len(suites)))
	contents = append(contents, suites...)

	contents = append(contents, maximumNameLength)
	contents = append(contents, uint8(len(publicName)))
	contents = append(contents, []byte(publicName)...)
	contents = appendU16(contents, 0) // no ECHConfig extensions

	if len(contents) > 0xffff {
		return nil, nil, errors.New("ECHConfig contents too large")
	}
	config := make([]byte, 0, 4+len(contents))
	config = appendU16(config, echVersion)
	config = appendU16(config, uint16(len(contents)))
	config = append(config, contents...)

	if len(config) > 0xffff {
		return nil, nil, errors.New("ECHConfig too large")
	}
	list := make([]byte, 0, 2+len(config))
	list = appendU16(list, uint16(len(config)))
	list = append(list, config...)
	return config, list, nil
}

func appendU16(dst []byte, v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return append(dst, b[:]...)
}

func validatePublicName(name string) error {
	if name == "" || len(name) > 255 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return errors.New("must be a non-empty DNS name without a leading/trailing dot")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("invalid DNS label")
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return errors.New("public name must use LDH DNS labels")
		}
	}
	return nil
}
