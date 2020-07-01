// Copyright 2019-2020 Moritz Fain
// Moritz Fain <moritz@fain.io>
package socks5proxy

import (
	"moproxy/internal/proxyconn"
	"moproxy/pkg/authenticator"
	"moproxy/pkg/config"
	"moproxy/pkg/misc"
	"moproxy/pkg/server/stats"

	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/maurice2k/tcpserver"
)

const (
	SOCKS5_VERSION = 0x05
)

// Command consts used in request
const (
	CMD_CONNECT       = 0x01
	CMD_BIND          = 0x02
	CMD_UDP_ASSOCIATE = 0x03 // not implemented
)

// Address types used in requests and replies
const (
	ATYP_IP_V4      = 0x01
	ATYP_DOMAINNAME = 0x03
	ATYP_IP_V6      = 0x04
)

// Authentication types
const (
	AUTH_NO_AUTH              = 0x00
	AUTH_GSSAPI               = 0x01 // not implemented
	AUTH_USERNAME_PASSWORD    = 0x02
	AUTH_NO_ACCEPTABLE_METHOD = 0xff
)

// Reply codes used in sendReply
const (
	REP_SUCCESS                     = 0x00
	REP_GENERAL_FAILURE             = 0x01
	REP_CONN_NOT_ALLOWED_BY_RULESET = 0x02
	REP_NET_UNREACHABLE             = 0x03
	REP_HOST_UNREACHABLE            = 0x04
	REP_CONN_REFUSED                = 0x05
	REP_TTL_EXPIRED                 = 0x06 // not used
	REP_COMMAND_NOT_SUPPORTED       = 0x07
	REP_ADDRESS_TYPE_NOT_SUPPORTED  = 0x08 // handled by direct connection termination
)

type Request struct {
	Command    byte
	LocalAddr  *net.TCPAddr
	RemoteAddr proxyconn.RemoteAddr
}

type socks5ClientConn struct {
	*proxyconn.ProxyConn
	request       *Request
	lastReplyCode byte
}

func sendReply(conn *socks5ClientConn, request *Request, replyCode byte) {
	/*  https://tools.ietf.org/html/rfc1928#section-6

	6.  Replies

	   The SOCKS request information is sent by the client as soon as it has
	   established a connection to the SOCKS server, and completed the
	   authentication negotiations.  The server evaluates the request, and
	   returns a reply formed as follows:

			+----+-----+-------+------+----------+----------+
			|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
			+----+-----+-------+------+----------+----------+
			| 1  |  1  | X'00' |  1   | Variable |    2     |
			+----+-----+-------+------+----------+----------+

		 Where:

			  o  VER    protocol version: X'05'
			  o  REP    Reply field:
				 o  X'00' succeeded
				 o  X'01' general SOCKS server failure
				 o  X'02' connection not allowed by ruleset
				 o  X'03' Network unreachable
				 o  X'04' Host unreachable
				 o  X'05' Connection refused
				 o  X'06' TTL expired
				 o  X'07' Command not supported
				 o  X'08' Address type not supported
				 o  X'09' to X'FF' unassigned
			  o  RSV    RESERVED
			  o  ATYP   address type of following address
				 o  IP V4 address: X'01'
				 o  DOMAINNAME: X'03'
				 o  IP V6 address: X'04'
			  o  BND.ADDR       server bound address
			  o  BND.PORT       server bound port in network octet order

	   Fields marked RESERVED (RSV) must be set to X'00'.

	   If the chosen method includes encapsulation for purposes of
	   authentication, integrity and/or confidentiality, the replies are
	   encapsulated in the method-dependent encapsulation.
	*/

	boundAddr := new(net.TCPAddr)
	if request.LocalAddr.IP != nil {
		// we already have a local address and port (remote connection is or was on the way to be established)
		boundAddr = request.LocalAddr
	} else {
		// no remote connection has been made yet; we're using a zero address in the format of the external bind address
		if misc.IsIPv6Addr(getExternalBindAddr(conn)) {
			boundAddr.IP = net.IPv6zero
		} else {
			boundAddr.IP = net.IPv4zero
		}
		boundAddr.Port = 0
	}

	var wr bytes.Buffer
	wr.Write([]byte{SOCKS5_VERSION, replyCode, 0x00})

	if misc.IsUnspecifiedIP(boundAddr.IP) && request.RemoteAddr.DomainName != "" {
		// kind of a special case to get cURLs error message more helpful
		wr.WriteByte(ATYP_DOMAINNAME)
		wr.WriteByte(byte(len(request.RemoteAddr.DomainName)))
		wr.Write([]byte(request.RemoteAddr.DomainName))
		boundAddr.Port = request.RemoteAddr.Port

	} else if ipv4 := boundAddr.IP.To4(); ipv4 != nil {
		wr.WriteByte(ATYP_IP_V4)
		wr.Write(ipv4)

	} else {
		wr.WriteByte(ATYP_IP_V6)
		wr.Write(boundAddr.IP[0:16])
	}

	binary.Write(&wr, binary.BigEndian, uint16(boundAddr.Port))

	n, _ := conn.Write(wr.Bytes())
	conn.AddWritten(int64(n))

	conn.lastReplyCode = replyCode
}

// validates SOCKS5 version
func validateVersion(conn *socks5ClientConn) bool {
	log := conn.GetLogger()
	ver := []uint8{0}
	n, err := io.ReadFull(conn, ver)
	conn.AddRead(int64(n))

	if err != nil {
		if misc.IsTimeoutError(err) {
			log.Debug().Msgf("Timeout while reading version after %s", time.Now().Sub(conn.GetStartTime()))
		}
		return false
	}

	if ver[0] != SOCKS5_VERSION {
		log.Debug().Msgf("Unsupported SOCKS version %d (but only 5 is supported)", ver[0])
		return false
	}
	return true
}

// authenticate request
func authenticate(conn *socks5ClientConn, authenticator authenticator.Authenticator) bool {
	/*
		   The client connects to the server, and sends a version
		   identifier/method selection message:

						   +----+----------+----------+
						   |VER | NMETHODS | METHODS  |
						   +----+----------+----------+
						   | 1  |    1     | 1 to 255 |
						   +----+----------+----------+

		   The VER field is set to X'05' for this version of the protocol.  The
		   NMETHODS field contains the number of method identifier octets that
		   appear in the METHODS field.

		   The server selects from one of the methods given in METHODS, and
		   sends a METHOD selection message:

								 +----+--------+
								 |VER | METHOD |
								 +----+--------+
								 | 1  |   1    |
								 +----+--------+

		   If the selected METHOD is X'FF', none of the methods listed by the
		   client are acceptable, and the client MUST close the connection.

		   The values currently defined for METHOD are:

				  o  X'00' NO AUTHENTICATION REQUIRED
				  o  X'01' GSSAPI
				  o  X'02' USERNAME/PASSWORD
				  o  X'03' to X'7F' IANA ASSIGNED
				  o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
				  o  X'FF' NO ACCEPTABLE METHODS

		   The client and server then enter a method-specific sub-negotiation.
	*/

	log := conn.GetLogger()

	if !validateVersion(conn) {
		return false
	}

	nmethods := []uint8{0}
	n, err := io.ReadFull(conn, nmethods)
	conn.AddRead(int64(n))

	if err != nil {
		if misc.IsTimeoutError(err) {
			log.Debug().Msgf("Timeout in authentication phase while reading number of authentication methods after %s", time.Now().Sub(conn.GetStartTime()))
		}
		return false
	}

	if nmethods[0] == 0 {
		log.Debug().Msgf("We need at least one authentication method!")
		return false
	}

	methods := make([]uint8, nmethods[0])
	n, err = io.ReadFull(conn, methods)
	conn.AddRead(int64(n))

	if err != nil {
		if misc.IsTimeoutError(err) {
			log.Debug().Msgf("Timeout in authentication phase while reading authentication methods after %s", time.Now().Sub(conn.GetStartTime()))
		}
		return false
	}

	authRequired := authenticator != nil

	if authRequired {
		log.Debug().Msgf("Authentication required using authenticator '%s'", authenticator.GetName())
	}

	var validAuthMethod uint8 = AUTH_NO_ACCEPTABLE_METHOD
	for i := 0; i < n; i++ {
		if authRequired && methods[i] == AUTH_USERNAME_PASSWORD {
			validAuthMethod = methods[i]
			break
		}

		if !authRequired && methods[i] == AUTH_NO_AUTH {
			validAuthMethod = methods[i]
			break
		}
	}

	n, _ = conn.Write([]uint8{SOCKS5_VERSION, validAuthMethod})
	conn.AddWritten(int64(n))

	if authRequired && validAuthMethod == AUTH_USERNAME_PASSWORD {
		authResult := authenticateUsernamePassword(conn, authenticator)
		if authResult == true {
			conn.SetSuccessfullyAuthenticated(authenticator)
		}
		return authResult
	}

	return validAuthMethod == AUTH_NO_AUTH
}

// Authenticate with username and password as defined in RFC 1929
func authenticateUsernamePassword(conn *socks5ClientConn, authenticator authenticator.Authenticator) bool {
	/* https://tools.ietf.org/html/rfc1929#section-2

	2.  Initial negotiation

	   Once the SOCKS V5 server has started, and the client has selected the
	   Username/Password Authentication protocol, the Username/Password
	   subnegotiation begins.  This begins with the client producing a
	   Username/Password request:

	           +----+------+----------+------+----------+
	           |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	           +----+------+----------+------+----------+
	           | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	           +----+------+----------+------+----------+

	   The VER field contains the current version of the subnegotiation,
	   which is X'01'. The ULEN field contains the length of the UNAME field
	   that follows. The UNAME field contains the username as known to the
	   source operating system. The PLEN field contains the length of the
	   PASSWD field that follows. The PASSWD field contains the password
	   association with the given UNAME.

	   The server verifies the supplied UNAME and PASSWD, and sends the
	   following response:

	                        +----+--------+
	                        |VER | STATUS |
	                        +----+--------+
	                        | 1  |   1    |
	                        +----+--------+

	   A STATUS field of X'00' indicates success. If the server returns a
	   `failure' (STATUS value other than X'00') status, it MUST close the
	   connection.

	*/

	verLen := make([]uint8, 2)
	n, _ := io.ReadFull(conn, verLen)
	conn.AddRead(int64(n))
	if n != len(verLen) {
		return false
	}

	if verLen[0] != 0x01 {
		return false
	}

	usernameLen := make([]uint8, verLen[1]+1)
	n, _ = io.ReadFull(conn, usernameLen)
	conn.AddRead(int64(n))
	if n != len(usernameLen) {
		return false
	}

	password := make([]uint8, usernameLen[verLen[1]])
	n, _ = io.ReadFull(conn, password)
	conn.AddRead(int64(n))
	if n != len(password) {
		return false
	}

	ok := authenticator.Authenticate(string(usernameLen[0:len(usernameLen)-1]), string(password), conn.GetClientAddr(), conn.GetInternalAddr())

	if ok {
		n, _ = conn.Write([]byte{0x01, 0x00})
		conn.AddWritten(int64(n))
		return true
	}

	n, _ = conn.Write([]byte{0x01, 0x01})
	conn.AddWritten(int64(n))
	return false
}

// reads and parses request
func readRequest(conn *socks5ClientConn) *Request {
	/*  https://tools.ietf.org/html/rfc1928#section-4

	4.  Requests

	   Once the method-dependent subnegotiation has completed, the client
	   sends the request details.  If the negotiated method includes
	   encapsulation for purposes of integrity checking and/or
	   confidentiality, these requests MUST be encapsulated in the method-
	   dependent encapsulation.

	   The SOCKS request is formed as follows:

			+----+-----+-------+------+----------+----------+
			|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
			+----+-----+-------+------+----------+----------+
			| 1  |  1  | X'00' |  1   | Variable |    2     |
			+----+-----+-------+------+----------+----------+

		 Where:

			  o  VER    protocol version: X'05'
			  o  CMD
				 o  CONNECT X'01'
				 o  BIND X'02'
				 o  UDP ASSOCIATE X'03'
			  o  RSV    RESERVED
			  o  ATYP   address type of following address
				 o  IP V4 address: X'01'
				 o  DOMAINNAME: X'03'
				 o  IP V6 address: X'04'
			  o  DST.ADDR       desired destination address
			  o  DST.PORT desired destination port in network octet
				 order

	   The SOCKS server will typically evaluate the request based on source
	   and destination addresses, and return one or more reply messages, as
	   appropriate for the request type.

	*/

	log := conn.GetLogger()

	if !validateVersion(conn) {
		return nil
	}

	reqHeader := make([]uint8, 3)
	n, err := io.ReadFull(conn, reqHeader)
	conn.AddRead(int64(n))

	if err != nil {
		if misc.IsTimeoutError(err) {
			log.Debug().Msgf("Timeout in negotiate phase while reading request header after %s", time.Now().Sub(conn.GetStartTime()))
		}
		return nil
	}

	request := &Request{
		Command:   reqHeader[0],
		LocalAddr: new(net.TCPAddr),
		RemoteAddr: proxyconn.RemoteAddr{
			TCPAddr: new(net.TCPAddr),
		},
	}

	addressType := reqHeader[2]
	if addressType == ATYP_IP_V4 {

		ip := make([]uint8, net.IPv4len)
		n, err = io.ReadFull(conn, ip)
		conn.AddRead(int64(n))

		if err != nil {
			log.Debug().Msgf("Unable to read remote IPv4 address (4 bytes)")
			return nil
		}
		request.RemoteAddr.IP = net.IP(ip)

	} else if addressType == ATYP_IP_V6 {

		ip := make([]uint8, net.IPv6len)
		n, err = io.ReadFull(conn, ip)
		conn.AddRead(int64(n))

		if err != nil {
			log.Debug().Msgf("Unable to read remote IPv6 address (16 bytes)")
			return nil
		}
		request.RemoteAddr.IP = net.IP(ip)

	} else if addressType == ATYP_DOMAINNAME {

		addrLen := []uint8{0}
		n, err = io.ReadFull(conn, addrLen)
		conn.AddRead(int64(n))

		if err != nil {
			log.Debug().Msgf("Unable to read remote domain name length (1 byte)")
			return nil
		}

		domainName := make([]uint8, addrLen[0])
		n, err = io.ReadFull(conn, domainName)
		conn.AddRead(int64(n))

		if err != nil {
			log.Debug().Msgf("Unable to read remote domain name (%d bytes)", addrLen[0])
			return nil
		}

		request.RemoteAddr.DomainName = string(domainName)

	} else {
		log.Debug().Msgf("Unsupported remote address type: %d", addressType)
		return nil

	}

	port := make([]uint8, 2)
	n, err = io.ReadFull(conn, port)
	conn.AddRead(int64(n))

	if err != nil {
		log.Debug().Msgf("Unable to read remote port (2 bytes)")
		return nil
	}
	request.RemoteAddr.Port = int(binary.BigEndian.Uint16(port))

	return request
}

func newSocks5Conn(conn *tcpserver.Connection) *socks5ClientConn {
	return &socks5ClientConn{ProxyConn: proxyconn.NewProxyConn(conn, config.PROXY_TYPE_SOCKS5)}
}

// TCP connection handler function
func HandlerFunc(conn *tcpserver.Connection) {
	s5Conn := newSocks5Conn(conn)

	conf := config.GetForServer(conn.GetServer())
	allowed, authenticator := conf.IsClientConnectionAllowed(s5Conn.ProxyConn)

	if !allowed {
		s5Conn.Log.Debug().Msgf("Connection from %s not allowed by ruleset (client rules)", conn.GetClientAddr().IP)
		return
	}

	tcpTimeouts := conf.GetTcpTimeouts()
	if tcpTimeouts.Negotiate > 0 {
		ts := time.Now().Add(time.Duration(tcpTimeouts.Negotiate))
		s5Conn.SetDeadline(ts)
	}

	if !authenticate(s5Conn, authenticator) {
		return
	}

	request := readRequest(s5Conn)
	if request == nil {
		return
	}

	s5Conn.request = request

	if tcpTimeouts.Idle > 0 {
		ts := time.Now().Add(time.Duration(tcpTimeouts.Idle))
		conn.SetDeadline(ts)
	}

	switch request.Command {
	case CMD_CONNECT:
		handleConnectCommand(s5Conn, request)

	case CMD_BIND:
		handleBindCommand(s5Conn, request)

	default:
		sendReply(s5Conn, request, REP_COMMAND_NOT_SUPPORTED)
		s5Conn.Log.Debug().Msgf("Unsupported command %d (only 1/CONNECT and 2/BIND are supported)", request.Command)
	}

	read, written := s5Conn.GetBytes()
	s5Conn.Log.Debug().Msgf("Client connection finished with status %d, written: %d, read: %d", s5Conn.lastReplyCode, written, read)
	stats.PushEvent(s5Conn.CreateStatsEvent())
}

type Server struct {
	*tcpserver.Server
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

// Returns external bind address from connection's context
func getExternalBindAddr(conn *socks5ClientConn) *net.TCPAddr {
	ctx := conn.GetServer().GetContext()
	return (*ctx).Value(proxyconn.CtxKey("externalAddr")).(*net.TCPAddr)
}

// Creates a statistics event
func (c *socks5ClientConn) CreateStatsEvent() stats.Event {
	read, written := c.GetBytes()
	event := stats.Event{
		ClientAddr:   c.GetClientAddr(),
		InternalAddr: c.GetInternalAddr(),
		ExternalAddr: c.GetExternalAddr(),
		RemoteAddr:   c.request.RemoteAddr.TCPAddr,

		BytesRead:    read,
		BytesWritten: written,

		SocksCommand:   c.request.Command,
		SocksReplyCode: c.lastReplyCode,

		Elapsed: time.Now().Sub(c.GetStartTime()),
	}

	return event
}
