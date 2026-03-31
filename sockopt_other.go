//go:build !linux

package main

import "net"

func applySocketOpts(conn net.Conn) {}
