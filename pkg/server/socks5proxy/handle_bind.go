// Copyright 2019-2020 Moritz Fain
// Moritz Fain <moritz@fain.io>
package socks5proxy

import (
	"moproxy/internal"
	"moproxy/pkg/config"

	"github.com/maurice2k/tcpserver"

	"net"
	"time"
)

func handleBindCommand(conn *socks5ClientConn, request *Request) {
	log := conn.GetLogger()

	bindAddr := getExternalBindAddr(conn)
	isBindAddrIPv6 := internal.IsIPv6Addr(bindAddr)

	if internal.IsUnspecifiedIP(request.RemoteAddr.IP) {
		// No IP set so far, we need to resolve the hostname
		// If the outgoing IP is an IPv6 address, try resolving to IPv6

		network := "ip4"
		if isBindAddrIPv6 {
			network = "ip6"
		}

		ip, err := net.ResolveIPAddr(network, request.RemoteAddr.DomainName)
		if err != nil {
			log.Debug().Msgf("Unable to resolve %s address of '%s'", network, request.RemoteAddr.DomainName)
			sendReply(conn, request, REP_HOST_UNREACHABLE)
			return
		}
		request.RemoteAddr.IP = ip.IP
	}

	tcpTimeouts := config.GetTcpTimeouts()

	if !config.IsProxyConnectionAllowed(conn.GetClientAddr().IP, request.RemoteAddr.IP) {
		log.Debug().Msgf("SOCKS 'BIND' not allowed by ruleset")
		sendReply(conn, request, REP_CONN_NOT_ALLOWED_BY_RULESET)
		return
	}

	bindServer, _ := tcpserver.NewServer(bindAddr.String())
	bindServer.SetMaxAcceptConnections(1)
	bindServer.SetRequestHandler(func (incomingConn *tcpserver.Connection) {
		if tcpTimeouts.Idle > 0 {
			ts := time.Now().Add(time.Duration(tcpTimeouts.Idle))
			incomingConn.SetDeadline(ts)
		}

		request.LocalAddr = incomingConn.GetClientAddr()
		sendReply(conn, request, REP_SUCCESS)

		// Start proxying
		var bytesWritten, bytesRead int64
		errCh := make(chan error, 2)
		go internal.ProxyTCP(incomingConn.Conn.(*net.TCPConn), conn.Conn.(*net.TCPConn), &bytesWritten, errCh)
		go internal.ProxyTCP(conn.Conn.(*net.TCPConn), incomingConn.Conn.(*net.TCPConn), &bytesRead, errCh)

		// Wait
		for i := 0; i < 2; i++ {
			e := <-errCh
			if e != nil {
				break
			}
		}

		conn.AddRead(bytesRead)
		conn.AddWritten(bytesWritten)

	})
	err := bindServer.Listen()
	if err != nil {
		log.Warn().Msgf("Unable to start listening while handling BIND command: %s", err.Error())
		sendReply(conn, request, REP_GENERAL_FAILURE)
		return
	}

	request.LocalAddr = bindServer.GetListenAddr()
	sendReply(conn, request, REP_SUCCESS)

	err = bindServer.Serve()
	if err != nil {
		log.Warn().Msgf("Error while accepting connections in BIND command: %s", err.Error())
		sendReply(conn, request, REP_GENERAL_FAILURE)
		return
	}

	return
}
