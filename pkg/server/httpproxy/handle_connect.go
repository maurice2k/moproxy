// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package httpproxy

import (
	"moproxy/internal"
	"moproxy/internal/proxyconn"

	"net"
	"net/http"
	"strconv"
)

func handleConnectMethod(conn *httpClientConn) {
	remoteAddr := &proxyconn.RemoteAddr{
		TCPAddr: new(net.TCPAddr),
	}

	host, portStr, err := net.SplitHostPort(conn.request.RequestURI)
	if err != nil {
		sendReply(conn, http.StatusBadRequest, "", err)
		return
	}

	ip := net.ParseIP(host)
	if ip != nil {
		remoteAddr.IP = ip
	} else {
		remoteAddr.DomainName = host
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		sendReply(conn, http.StatusBadRequest, "", err)
		return
	}
	remoteAddr.Port = port

	remoteTCPConn, err := internal.ConnectToRemote(conn.ProxyConn, remoteAddr)
	if err != nil {
		if rcErr, ok := err.(*internal.RemoteConnError); ok {
			switch rcErr.Type {
			case internal.ErrNotAllowedByRuleset:
				conn.Log.Debug().Msgf("Not allowed to connect to remote: %s", err)
				sendReply(conn, http.StatusForbidden, "", err)
			case internal.ErrNetUnreachable:
				fallthrough
			case internal.ErrHostUnreachable:
				fallthrough
			case internal.ErrConnRefused:
				fallthrough
			default:
				conn.Log.Debug().Msgf("Unable to connect to remote: %s", err)
				sendReply(conn, http.StatusBadGateway, "", err)
			}
		} else {
			// should not happen
			sendReply(conn, http.StatusInternalServerError, "", err)
		}
		return
	}

	defer remoteTCPConn.Close()

	sendReply(conn, http.StatusOK, "Connection established! Go ahead!", err)

	// Start proxying
	var bytesWritten, bytesRead int64
	errCh := make(chan error, 2)
	go internal.ProxyTCP(conn.TCPConn.Conn, remoteTCPConn, &bytesRead, errCh)
	go internal.ProxyTCP(remoteTCPConn, conn.TCPConn.Conn, &bytesWritten, errCh)

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
