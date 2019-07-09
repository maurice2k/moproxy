// Copyright 2019-2020 Moritz Fain
// Moritz Fain <moritz@fain.io>

// +build !linux

package internal

import (
	"github.com/rs/zerolog"

	"syscall"
)

type controlFunc func(network, address string, c syscall.RawConn) error

func applyRemoteConnSocketOptions(log zerolog.Logger) controlFunc {
	return func(network, address string, c syscall.RawConn) error {
		return nil
	}
}
