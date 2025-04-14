// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package httpproxy

import (
	"moproxy/internal"
	"moproxy/internal/proxyconn"
	"moproxy/pkg/misc"

	"bufio"
	"net"
	"net/http"
	"regexp"
	"strconv"
)

func handleGenericHttpMethod(conn *httpClientConn) {
	conn.request.RequestURI = ""
	// always set a user agent (even if blank) to prevent default golang user agent to be added
	conn.request.Header.Set("User-Agent", conn.request.Header.Get("User-Agent"))
	conn.request.Header.Del("Proxy-Authorization")

	remoteAddr := &proxyconn.RemoteAddr{
		TCPAddr: new(net.TCPAddr),
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

	// Write the request to remote
	conn.request.Write(remoteTCPConn)

	// Read the response from remote ...
	br := bufio.NewReader(remoteTCPConn)
	response, err := http.ReadResponse(br, conn.request)

	// ... and write it to the client
	cw := misc.NewCountWriter(conn)
	response.Write(cw)

	conn.AddWritten(int64(cw.GetCountAndReset()))

	return
}
