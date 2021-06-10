// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package proxyconn

import (
	"moproxy/pkg/auth"

	"net"

	"github.com/maurice2k/tcpserver"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type CtxKey string

// ProxyConn describes the connection between client and proxy server
type ProxyConn struct {
	*tcpserver.TCPConn
	externalAddr  *net.TCPAddr
	Log           zerolog.Logger
	read, written int64
	authenticated bool
	authenticator auth.Authenticator
	proxyType     int
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

func NewProxyConn(conn *tcpserver.TCPConn, proxyType int) *ProxyConn {
	c := &ProxyConn{
		TCPConn:   conn,
		read:      0,
		written:   0,
		proxyType: proxyType,
	}

	return c
}

// Reset is called is used by tcpserver to re-use the ProxyConn instance
func (c *ProxyConn) Reset(netConn net.Conn) {
	c.TCPConn.Reset(netConn)

	c.Log = log.With().
		Str("client_addr", c.GetClientAddr().String()).
		Str("internal_addr", c.GetInternalAddr().String()).
		Str("external_addr", c.GetExternalAddr().String()).
		Logger()

	c.externalAddr = nil
	c.read = 0
	c.written = 0
	c.authenticated = false
	c.authenticator = nil
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

func (c *ProxyConn) GetProxyType() int {
	return c.proxyType
}

// GetInternalAddr returns internal socks5 address at which this connection was accepted
func (c *ProxyConn) GetInternalAddr() *net.TCPAddr {
	return c.GetServerAddr()
}

// GetExternalAddr returns the external socks5 address that is used for outgoing connections
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

// SetSuccessfullyAuthenticated flags this connection as successfully authenticated with given authenticator name
func (c *ProxyConn) SetSuccessfullyAuthenticated(authenticator auth.Authenticator) {
	c.authenticated = true
	c.authenticator = authenticator
}

// IsSuccessfullyAuthenticated checks whether this connection has been successfully authenticated
func (c *ProxyConn) IsSuccessfullyAuthenticated() (authenticated bool, authenticator auth.Authenticator) {
	return c.authenticated, c.authenticator
}
