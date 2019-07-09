package authenticator

import (
	"net"
)

type staticAuth struct {
	username string
	password string
}

func NewStaticAuth(username, password string) Authenticator {
	return &staticAuth{
		username: username,
		password: password,
	}
}

func (auth *staticAuth) Authenticate(username, password string, clientAddr, serverAddr *net.TCPAddr) bool {
	return auth.username == username && auth.password == password
}
