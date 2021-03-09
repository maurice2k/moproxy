package auth
/*
import (
	"net"
)

type binaryAuth struct {
	basicAuth
	path         string
	maxProcs     int
	idleProcs    int
	startupProcs int
}

func NewBinaryAuth(path string, maxProcs int, idleProcs int, startupProcs int) Authenticator {
	return &binaryAuth{
		path:         path,
		maxProcs:     maxProcs,
		idleProcs:    idleProcs,
		startupProcs: startupProcs,
	}
}

func (auth *binaryAuth) Authenticate(username, password string, clientAddr, serverAddr *net.TCPAddr) bool {
	return auth.username == username && auth.password == password
}
*/