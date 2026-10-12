//go:build !linux

package main

import "log"

func main() {
	log.Fatal("mist-edge currently supports Linux only")
}
