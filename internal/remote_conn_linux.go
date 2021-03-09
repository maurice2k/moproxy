// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package internal

import (
	"github.com/rs/zerolog"

	"syscall"
)

const TCP_FASTOPEN_CONNECT = 0x1e

type controlFunc func(network, address string, c syscall.RawConn) error

func applyRemoteConnSocketOptions(log zerolog.Logger) controlFunc {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1)
			if err != nil {
				log.Error().Msgf("Unable to set TCP_FASTOPEN_CONNECT option: %s", err.Error())
			}
		})
	}
}
