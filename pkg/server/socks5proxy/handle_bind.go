// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package socks5proxy

import (
	"moproxy/internal"
	"moproxy/pkg/config"
	"moproxy/pkg/misc"

	"net"

	"github.com/maurice2k/tcpserver"
)

func handleBindCommand(conn *socks5ClientConn, request *Request) {
	log := conn.GetLogger()

	bindAddr := getExternalBindAddr(conn)
	isBindAddrIPv6 := misc.IsIPv6Addr(bindAddr)

	if misc.IsUnspecifiedIP(request.RemoteAddr.IP) {
		// No IP set so far, we need to resolve the hostname
		// If the outgoing IP is an IPv6 address, try resolving to IPv6

		network := "ip4"
		if isBindAddrIPv6 {
			network = "ip6"
		}

		ip, err := net.ResolveIPAddr(network, request.RemoteAddr.DomainName)
		if err != nil {
			log.Debug().Msgf("Unable to resolve %s address of '%s'", network, request.RemoteAddr.DomainName)
			sendReply(conn, request, RepHostUnreachable)
			return
		}
		request.RemoteAddr.IP = ip.IP
	}

	conf := config.GetForServer(conn.GetServer())
	tcpTimeouts := conf.GetTcpTimeouts()

	if !conf.IsProxyConnectionAllowed(conn.ProxyConn, request.RemoteAddr.IP) {
		log.Debug().Msgf("SOCKS 'BIND' not allowed by ruleset (proxy rules)")
		sendReply(conn, request, RepConnNotAllowedByRuleset)
		return
	}

	bindServer, _ := tcpserver.NewServer(bindAddr.String())
	bindServer.SetMaxAcceptConnections(1)
	bindServer.SetRequestHandler(func(incomingConn tcpserver.Connection) {

		request.LocalAddr = incomingConn.GetClientAddr()
		sendReply(conn, request, RepSuccess)

		// Start proxying
		var bytesWritten, bytesRead int64
		errCh := make(chan error, 2)
		go internal.ProxyTCP(incomingConn.(*tcpserver.TCPConn).Conn, conn.Conn, &bytesWritten, errCh)
		go internal.ProxyTCP(conn.Conn, incomingConn.(*tcpserver.TCPConn).Conn, &bytesRead, errCh)

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
		sendReply(conn, request, RepGeneralFailure)
		return
	}

	request.LocalAddr = bindServer.GetListenAddr()
	sendReply(conn, request, RepSuccess)

	err = bindServer.Serve()
	if err != nil {
		log.Warn().Msgf("Error while accepting connections in BIND command: %s", err.Error())
		sendReply(conn, request, RepGeneralFailure)
		return
	}

	return
}
