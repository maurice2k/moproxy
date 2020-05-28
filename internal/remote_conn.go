package internal

import (
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"moproxy/pkg/config"
)

// error type consts; these are numerically identical to SOCKS5 reply codes
const (
	ERR_NOT_ALLOWED_BY_RULESET = 0x02
	ERR_NET_UNREACHABLE        = 0x03
	ERR_HOST_UNREACHABLE       = 0x04
	ERR_CONN_REFUSED           = 0x05
)

type RemoteConnError struct {
	msg  string
	Type byte
	Err  error
}

func (e *RemoteConnError) Unwrap() error { return e.Err }
func (e *RemoteConnError) Error() string {
	return e.msg
}

func ConnectToRemote(clientConn *ProxyConn, remoteAddr *RemoteAddr) (*net.TCPConn, error) {
	log := clientConn.Log
	externalAddr := clientConn.GetExternalAddr()
	isExternalAddrIPv6 := IsIPv6Addr(externalAddr)

	if IsUnspecifiedIP(remoteAddr.IP) {
		// No IP set so far, we need to resolve the hostname
		// If the external IP is an IPv6 address, try resolving to IPv6

		network := "ip4"
		if isExternalAddrIPv6 {
			network = "ip6"
		}

		clientConn.Log = log.With().Str("remote_domain", remoteAddr.DomainName).Logger()
		log = clientConn.Log

		ip, err := net.ResolveIPAddr(network, remoteAddr.DomainName)
		if err != nil {
			return nil, &RemoteConnError{msg: fmt.Sprintf("Unable to resolve %s address of '%s'", network, remoteAddr.DomainName), Type: ERR_HOST_UNREACHABLE, Err: err}
		}
		remoteAddr.IP = ip.IP
	}

	clientConn.Log = log.With().Str("remote_addr", remoteAddr.TCPAddr.String()).Logger()
	log = clientConn.Log

	network := "tcp4"
	if isExternalAddrIPv6 {
		network = "tcp6"
	}

	tcpTimeouts := config.GetTcpTimeouts()
	remoteDialer := net.Dialer{
		LocalAddr: externalAddr,
	}

	if config.GetTuningConfig().TFOOutgoing {
		remoteDialer.Control = applyRemoteConnSocketOptions(log)
	}

	if tcpTimeouts.Connect > 0 {
		ts := time.Now().Add(time.Duration(tcpTimeouts.Connect))
		remoteDialer.Deadline = ts
	}

	if !config.IsProxyConnectionAllowed(clientConn.GetClientAddr().IP, remoteAddr.IP) {
		return nil, &RemoteConnError{msg: fmt.Sprintf("Client to remote not allowed by ruleset"), Type: ERR_NOT_ALLOWED_BY_RULESET, Err: nil}
	}

	remoteConn, err := remoteDialer.Dial(network, remoteAddr.TCPAddr.String())
	if err != nil {

		errType := byte(ERR_HOST_UNREACHABLE)

		if IsTimeoutError(err) {
			return nil, &RemoteConnError{msg: fmt.Sprintf("Timeout connecting to remote address '%s' with error: %s after %s", remoteAddr, err, time.Now().Sub(clientConn.GetStartTime())), Type: ERR_HOST_UNREACHABLE, Err: err}

		} else if strings.Contains(err.Error(), "network is unreachable") {
			errType = ERR_NET_UNREACHABLE

		} else if strings.Contains(err.Error(), "connection refused") {
			errType = ERR_CONN_REFUSED

		}

		return nil, &RemoteConnError{msg: fmt.Sprintf("Unable to connect to remote address '%s' with error: %s", remoteAddr, err), Type: errType, Err: err}
	}

	// update external addr in logger
	clientConn.Log = clientConn.Log.With().
		Str("external_addr", remoteConn.LocalAddr().String()).
		Logger()

	clientConn.Log.Debug().Msg("Connection established")


	return remoteConn.(*net.TCPConn), nil
}

// Copies data from one connection to the other and sends errors to the given errChan
// src and dst should be of type *net.TCPConn (and not derived) so that io.Copy is able
// to use zero-copy splice/sendfile optimizations where available
func ProxyTCP(src *net.TCPConn, dst *net.TCPConn, copied *int64, errChan chan error) {
	n, err := io.Copy(dst, src)
	atomic.AddInt64(copied, n)
	dst.CloseWrite()
	errChan <- err
}
