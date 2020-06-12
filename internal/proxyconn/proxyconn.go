// Copyright 2019-2020 Moritz Fain
// Moritz Fain <moritz@fain.io>
package proxyconn

import (
	"net"

	"github.com/maurice2k/tcpserver"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type CtxKey string

type ProxyConn struct {
	*tcpserver.Connection
	externalAddr      *net.TCPAddr
	Log               zerolog.Logger
	read, written     int64
	authenticated     bool
	authenticatorName string
}

type RemoteAddr struct {
	*net.TCPAddr
	DomainName string
}

func (r RemoteAddr) String() string {
	if r.DomainName != "" {
		return r.TCPAddr.String() + " [" + r.DomainName + "]"
	}
	return r.TCPAddr.String()
}

func NewProxyConn(conn *tcpserver.Connection) *ProxyConn {
	c := &ProxyConn{
		Connection: conn,
		read:       0,
		written:    0,
	}

	c.Log = log.With().
		Str("client_addr", c.GetClientAddr().String()).
		Str("internal_addr", c.GetInternalAddr().String()).
		Str("external_addr", c.GetExternalAddr().String()).
		Logger()

	return c
}

func (c *ProxyConn) AddWritten(numBytes int64) {
	c.written += numBytes
}

func (c *ProxyConn) AddRead(numBytes int64) {
	c.read += numBytes
}

func (c *ProxyConn) GetBytes() (read, written int64) {
	return c.read, c.written
}

func (c *ProxyConn) GetLogger() zerolog.Logger {
	return c.Log
}

// Returns internal socks5 address at which this connection was accepted
func (c *ProxyConn) GetInternalAddr() *net.TCPAddr {
	return c.GetServerAddr()
}

// Returns the external socks5 address that is used for outgoing connections
func (c *ProxyConn) GetExternalAddr() *net.TCPAddr {
	if c.externalAddr == nil {
		ctx := c.GetServer().GetContext()
		extAddr := (*ctx).Value(CtxKey("externalAddr")).(*net.TCPAddr)

		c.externalAddr = &net.TCPAddr{}
		*c.externalAddr = *extAddr
	}

	if c.externalAddr.IP.IsUnspecified() {
		// In case the external IP is either 0.0.0.0 or [::] we're trying to set it to the listening IP address
		// (or more specific: it is set to the concrete IP address the client connected to). That way, the traffic
		// is leaving the server using the same IP address that was used when connecting to moproxy.

		// This is useful if moproxy is running on a server with multiple IP addresses and is configured to listen on
		// "0.0.0.0:1080" without a specific external IP.

		c.externalAddr.IP = c.GetServerAddr().IP
	}

	return c.externalAddr
}

// Flags this connection as successfully authenticated with given authenticator name
func (c *ProxyConn) SetSuccessfullyAuthenticated(authenticatorName string) {
	c.authenticated = true
	c.authenticatorName = authenticatorName
}

// Returns whether this connection has been successfully authenticated
func (c *ProxyConn) IsSuccessfullyAuthenticated() (authenticated bool, authenticatorName string) {
	return c.authenticated, c.authenticatorName
}
