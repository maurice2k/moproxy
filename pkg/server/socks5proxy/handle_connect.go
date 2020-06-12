// Copyright 2019-2020 Moritz Fain
// Moritz Fain <moritz@fain.io>
package socks5proxy

import (
	"moproxy/internal"

	"net"
)

func handleConnectCommand(conn *socks5ClientConn, request *Request) {
	remoteTCPConn, err := internal.ConnectToRemote(conn.ProxyConn, &request.RemoteAddr)
	if err != nil {
		if rcErr, ok := err.(*internal.RemoteConnError); ok {
			conn.Log.Debug().Msgf("Unable to connect to remote: %s", err)
			sendReply(conn, request, rcErr.Type)
		} else {
			// should not happen
			sendReply(conn, request, REP_HOST_UNREACHABLE)
		}
		return
	}

	defer remoteTCPConn.Close()

	request.LocalAddr = remoteTCPConn.LocalAddr().(*net.TCPAddr)

	sendReply(conn, request, REP_SUCCESS)

	// Start proxying
	var bytesWritten, bytesRead int64
	errCh := make(chan error, 2)
	go internal.ProxyTCP(conn.Connection.Conn.(*net.TCPConn), remoteTCPConn, &bytesRead, errCh)
	go internal.ProxyTCP(remoteTCPConn, conn.Connection.Conn.(*net.TCPConn), &bytesWritten, errCh)

	// Wait
	for i := 0; i < 2; i++ {
		e := <-errCh
		if e != nil {
			break
		}
	}

	conn.AddRead(bytesRead)
	conn.AddWritten(bytesWritten)

	return
}

