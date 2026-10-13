//go:build !linux

package main

type hostSampler struct{}

func (*hostSampler) sample() map[string]any { return map[string]any{"available": false} }
