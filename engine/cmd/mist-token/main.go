package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sanderstripa/vpn/mist/internal/auth"
)

func main() {
	secret := flag.String("secret", "", "HMAC secret (or set MIST_TOKEN_SECRET)")
	clientID := flag.String("client", "", "client identifier")
	ttl := flag.Duration("ttl", 15*time.Minute, "token lifetime (max 24h)")
	flag.Parse()
	if *secret == "" { *secret = os.Getenv("MIST_TOKEN_SECRET") }
	if *secret == "" || *clientID == "" { log.Fatal("-secret/MIST_TOKEN_SECRET and -client are required") }
	tok, err := auth.Mint(*secret, *clientID, time.Now(), *ttl)
	if err != nil { log.Fatal(err) }
	fmt.Println(tok)
}
