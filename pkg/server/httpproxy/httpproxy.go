// Copyright 2019-2020 Moritz Fain
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

func newHttpConn(conn *tcpserver.Connection) *httpClientConn {
	return &httpClientConn{ProxyConn: proxyconn.NewProxyConn(conn, config.PROXY_TYPE_HTTP)}
}


// TCP connection handler function
func HandlerFunc(conn *tcpserver.Connection) {
	httpConn := newHttpConn(conn)

	log := httpConn.Log

	conf := config.GetForServer(httpConn.GetServer())

	allowed, authenticator := conf.IsClientConnectionAllowed(httpConn.ProxyConn)
	// We could have dropped the connection right away if not allowed, but
	// this seems to confuse some clients. We wait for the HTTP request and
	// send a proper HTTP response... see below.

	tcpTimeouts := conf.GetTcpTimeouts()
	httpTimeouts := conf.GetHttpTimeouts()

	br := brPool.Get().(*bufio.Reader)
	cr := misc.NewCountReader(httpConn)
	br.Reset(cr)

	reHttpPrefix, _ := regexp.Compile("^https?://")

	for {
		var err error

		if tcpTimeouts.Negotiate > 0 {
			ts := time.Now().Add(time.Duration(tcpTimeouts.Negotiate))
			httpConn.SetDeadline(ts)
		}
		httpConn.request, err = http.ReadRequest(br)
		httpConn.AddRead(int64(cr.GetCountAndReset()))

		if err != nil {
			log.Debug().Msgf("http.ReadRequest failed: %s", err)
			sendReply(httpConn, http.StatusBadRequest, "", err)
			break
		}

		connectRequest := httpConn.request.Method == "CONNECT"

		log = log.With().Str("remote", httpConn.request.RequestURI).Logger()
		httpConn.Log = log

		if !allowed {
			log.Debug().Msgf("Connection from %s not allowed by ruleset (client rules)", conn.GetClientAddr().IP)
			sendReply(httpConn, http.StatusForbidden, "", nil)
			return
		}

		if authenticator != nil {

			log.Debug().Msgf("Authentication required using authenticator '%s'", authenticator.GetName())

			proxyAuth := httpConn.request.Header.Get("Proxy-Authorization")
			username, password, ok := parseBasicAuth(proxyAuth)

			if ok {
				ok = authenticator.Authenticate(username, password, httpConn.GetClientAddr(), httpConn.GetInternalAddr())
			}

			if !ok {
				sendReply(httpConn, http.StatusProxyAuthRequired, "", err)
				break
			}

			httpConn.SetSuccessfullyAuthenticated(authenticator)
		}

		if connectRequest {
			log.Debug().Msgf("CONNECT request for %s", httpConn.request.RequestURI)

			handleConnectMethod(httpConn)
			break

		} else {

			if !reHttpPrefix.MatchString(httpConn.request.RequestURI) {
				sendReply(httpConn, 400, "", nil)
				break
			}

			log.Debug().Msgf("HTTP request for %s", httpConn.request.RequestURI)

			httpConn.request.RequestURI = ""
			// always set a user agent (even if blank) to prevent default golang user agent to be added
			httpConn.request.Header.Set("User-Agent", httpConn.request.Header.Get("User-Agent"))
			httpConn.request.Header.Del("Proxy-Authorization")

			handleGenericHttpMethod(httpConn)

			ts := time.Now().Add(time.Duration(httpTimeouts.KeepAlive))
			httpConn.SetDeadline(ts)
			_, err = br.Peek(1)
			if misc.IsTimeoutError(err) {
				log.Debug().Msgf("Idle timeout for proxy connection from %s reached", httpConn.GetClientAddr())
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
	s.SetRequestHandler(HandlerFunc)
	return s
}

// copied from https://golang.org/src/net/http/request.go#L935
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