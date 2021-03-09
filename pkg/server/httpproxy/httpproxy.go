// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package httpproxy

import (
	"moproxy/internal/proxyconn"
	"moproxy/pkg/config"
	"moproxy/pkg/misc"

	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/maurice2k/tcpserver"
)

type Server struct {
	*tcpserver.Server
}

type httpClientConn struct {
	*proxyconn.ProxyConn
	remoteAddr *proxyconn.RemoteAddr
	request    *http.Request
}

var brPool = &sync.Pool{
	New: func() interface{} {
		return bufio.NewReader(nil)
	},
}

func sendReply(conn *httpClientConn, statusCode int, statusText string, err error) {
	var buf = make([]byte, 0, 512)
	var proto = "HTTP/1.0"
	var additionalHeaders, content string

	if conn.request != nil && conn.request.Proto != "" {
		proto = conn.request.Proto
	}

	if statusText == "" {
		statusText = http.StatusText(statusCode)
	}

	if statusCode == http.StatusProxyAuthRequired {
		additionalHeaders = "Proxy-Authenticate: Basic realm=\"moproxy\""
	}

	if additionalHeaders != "" {
		additionalHeaders = "\r\n" + additionalHeaders
	}

	if err != nil {
		content = err.Error()
	}
	if content == "" && statusCode >= 300 {
		content = statusText
	}

	buf = append(buf, fmt.Sprintf("%s %d %s\r\nServer: moproxy\r\nContent-Length: %d\r\nConnection: close%s\r\n\r\n", proto, statusCode, statusText, len(content), additionalHeaders)...)
	if content != "" {
		buf = append(buf, content...)
	}

	n, _ := conn.Write(buf)
	conn.AddWritten(int64(n))
}

// Connect handles a new TCP connection
func Connect(conn *httpClientConn) {
	log := conn.Log

	conf := config.GetForServer(conn.GetServer())

	allowed, authenticator := conf.IsClientConnectionAllowed(conn.ProxyConn)
	// We could have dropped the connection right away if not allowed, but
	// this seems to confuse some clients. We wait for the HTTP request and
	// send a proper HTTP response... see below.

	tcpTimeouts := conf.GetTcpTimeouts()
	httpTimeouts := conf.GetHttpTimeouts()

	br := brPool.Get().(*bufio.Reader)
	cr := misc.NewCountReader(conn)
	br.Reset(cr)

	reHttpPrefix, _ := regexp.Compile("^https?://")

	for {
		var err error

		if tcpTimeouts.Negotiate > 0 {
			ts := time.Now().Add(time.Duration(tcpTimeouts.Negotiate))
			_ = conn.SetDeadline(ts)
		}
		conn.request, err = http.ReadRequest(br)
		conn.AddRead(int64(cr.GetCountAndReset()))

		if err != nil {
			log.Debug().Msgf("http.ReadRequest failed: %s", err)
			sendReply(conn, http.StatusBadRequest, "", err)
			break
		}

		connectRequest := conn.request.Method == "CONNECT"

		log = log.With().Str("remote", conn.request.RequestURI).Logger()
		conn.Log = log

		if !allowed {
			log.Debug().Msgf("Connection from %s not allowed by ruleset (client rules)", conn.GetClientAddr().IP)
			sendReply(conn, http.StatusForbidden, "", nil)
			return
		}

		if authenticator != nil {

			log.Debug().Msgf("Authentication required using authenticator '%s'", authenticator.GetName())

			proxyAuth := conn.request.Header.Get("Proxy-Authorization")
			username, password, ok := parseBasicAuth(proxyAuth)

			if ok {
				ok = authenticator.Authenticate(username, password, conn.GetClientAddr(), conn.GetInternalAddr())
			}

			if !ok {
				sendReply(conn, http.StatusProxyAuthRequired, "", err)
				break
			}

			conn.SetSuccessfullyAuthenticated(authenticator)
		}

		if connectRequest {
			log.Debug().Msgf("CONNECT request for %s", conn.request.RequestURI)

			handleConnectMethod(conn)
			break

		} else {

			if !reHttpPrefix.MatchString(conn.request.RequestURI) {
				sendReply(conn, 400, "", nil)
				break
			}

			log.Debug().Msgf("HTTP request for %s", conn.request.RequestURI)

			handleGenericHttpMethod(conn)

			log.Debug().Msg("DONE")

			ts := time.Now().Add(time.Duration(httpTimeouts.KeepAlive))
			_ = conn.SetDeadline(ts)
			_, err = br.Peek(1)
			if misc.IsTimeoutError(err) {
				log.Debug().Msgf("Idle timeout for proxy connection from %s reached", conn.GetClientAddr())
				break
			}
		}
	}
	brPool.Put(br)
}

func NewServer(listenAddr string, externalIp string, configInstance *config.Configuration) *Server {
	server, _ := tcpserver.NewServer(listenAddr)

	lc := &tcpserver.ListenConfig{SocketReusePort: true}
	server.SetListenConfig(lc)

	ctx := context.WithValue(*server.GetContext(), proxyconn.CtxKey("externalAddr"), &net.TCPAddr{IP: net.ParseIP(externalIp)})
	ctx = context.WithValue(ctx, proxyconn.CtxKey("config"), configInstance)
	server.SetContext(&ctx)

	s := &Server{server}
	s.SetConnectionCreator(func() tcpserver.Connection {
		return &httpClientConn{ProxyConn: proxyconn.NewProxyConn(&tcpserver.TCPConn{}, config.ProxyTypeHttp)}
	})
	s.SetRequestHandler(func(tcpserverConn tcpserver.Connection) {
		Connect(tcpserverConn.(*httpClientConn))
	})
	return s
}

// Reset is called from tcpserver to re-use the httpClientConn instance
func (c *httpClientConn) Reset(netConn net.Conn) {
	c.ProxyConn.Reset(netConn)
	c.request = nil
	c.remoteAddr = nil
}

// copied from https://golang.org/src/net/http/request.go#L945
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	// Case insensitive prefix match. See Issue 22736.
	if len(auth) < len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return
	}
	c, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}
	return cs[:s], cs[s+1:], true
}