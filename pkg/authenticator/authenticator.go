package authenticator

import (
	"net"
)

type Authenticator interface {
	Authenticate(username, password string, clientAddr, serverAddr *net.TCPAddr) bool
}
