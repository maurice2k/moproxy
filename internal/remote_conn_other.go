// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

// +build !linux

package internal

import (
	"syscall"

	"github.com/rs/zerolog"
)

type controlFunc func(network, address string, c syscall.RawConn) error

//goland:noinspection GoUnusedParameter
func applyRemoteConnSocketOptions(log zerolog.Logger) controlFunc {
	return func(network, address string, c syscall.RawConn) error {
		return nil
	}
}
