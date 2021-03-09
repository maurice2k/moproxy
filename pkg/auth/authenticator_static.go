package auth

import (
	"net"
)

type staticAuth struct {
	basicAuth
	username string
	password string
}

func NewStaticAuth(username, password string) Authenticator {
	return &staticAuth{
		username: username,
		password: password,
	}
}

//goland:noinspection GoUnusedParameter
func (auth *staticAuth) Authenticate(username, password string, clientAddr, serverAddr *net.TCPAddr) bool {
	return auth.username == username && auth.password == password
}
