// Copyright 2019-2020 Moritz Fain
// Moritz Fain <moritz@fain.io>
package internal

import (
	"io"
	"net"
	"sync/atomic"

	"github.com/maurice2k/tcpserver"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type CtxKey string

type ProxyConn struct {
	*tcpserver.Connection
	externalAddr  *net.TCPAddr
	Log           zerolog.Logger
	read, written int64
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

// CountReader counts bytes read from io.Reader
type CountReader struct {
	io.Reader
	count uint64
}

func NewCountReader(r io.Reader) *CountReader {
	return &CountReader{
		Reader: r,
	}
}

func (cr *CountReader) Read(buf []byte) (int, error) {
	n, err := cr.Reader.Read(buf)
	atomic.AddUint64(&cr.count, uint64(n))
	return n, err
}

func (cr *CountReader) GetCount() uint64 {
	return atomic.LoadUint64(&cr.count)
}

func (cr *CountReader) GetCountAndReset() uint64 {
	return atomic.SwapUint64(&cr.count, 0)
}

// CountWriter counts bytes written to io.Writer
type CountWriter struct {
	io.Writer
	count uint64
}

func NewCountWriter(w io.Writer) *CountWriter {
	return &CountWriter{
		Writer: w,
	}
}

func (cw *CountWriter) Write(buf []byte) (int, error) {
	n, err := cw.Writer.Write(buf)
	atomic.AddUint64(&cw.count, uint64(n))
	return n, err
}

func (cw *CountWriter) GetCount() uint64 {
	return atomic.LoadUint64(&cw.count)
}

func (cw *CountWriter) GetCountAndReset() uint64 {
	return atomic.SwapUint64(&cw.count, 0)
}

// checks whether an error is a timeout "OpError"
func IsTimeoutError(err error) bool {
	opErr, ok := err.(*net.OpError)
	return ok && opErr.Timeout()
}

func IsIPv6Addr(addr *net.TCPAddr) bool {
	return addr.IP.To4() == nil && len(addr.IP) == net.IPv6len
}

func IsUnspecifiedIP(ip net.IP) bool {
	return ip == nil || len(ip) == 0 || ip.IsUnspecified()
}
