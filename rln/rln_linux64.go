//go:build !android && linux && amd64 && !musl
// +build !android,linux,amd64,!musl

package rln

/*
#cgo LDFLAGS: -L${SRCDIR}/../libs/x86_64-unknown-linux-gnu -lrln -ldl -lm -lpthread
*/
import "C"
