// Copyright 2019-2020 Moritz Fain
// Moritz Fain <moritz@fain.io>
package httpproxy

import (
	"moproxy/internal"
	"moproxy/internal/proxyconn"

	"bufio"
	"net"
	"net/http"
	"regexp"
	"strconv"
)

func handleGenericHttpMethod(conn *httpClientConn) {
	remoteAddr := &proxyconn.RemoteAddr{
		TCPAddr:    new(net.TCPAddr),
	}

	var host, portStr string
	var err error
	host = conn.request.Host

	if !regexp.MustCompile(":\\d+$").MatchString(host) {
		portStr = "80"
	} else {
		host, portStr, err = net.SplitHostPort(host)
		if err != nil {
			sendReply(conn, http.StatusBadRequest, "", err)
			return
		}
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
			case internal.ERR_NOT_ALLOWED_BY_RULESET:
				sendReply(conn, http.StatusForbidden, "", err)
			case internal.ERR_NET_UNREACHABLE:
			case internal.ERR_HOST_UNREACHABLE:
			case internal.ERR_CONN_REFUSED:
			default:
				sendReply(conn, http.StatusBadGateway, "", err)
			}
		} else {
			// should not happen
			sendReply(conn, http.StatusInternalServerError, "", err)
		}
		return
	}

	defer remoteTCPConn.Close()

	// Start proxying

	conn.request.Write(remoteTCPConn)

	br := bufio.NewReader(remoteTCPConn)
	response, err := http.ReadResponse(br, conn.request)

	cw := internal.NewCountWriter(conn)
	response.Write(cw)

	conn.AddWritten(int64(cw.GetCountAndReset()))

	return
}
