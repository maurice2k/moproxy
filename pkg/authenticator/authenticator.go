package authenticator

import (
	"net"
)

type Authenticator interface {
	// Authenticate user with a subset of username, password, client and server address
	Authenticate(username, password string, clientAddr, serverAddr *net.TCPAddr) bool

	// Sets name of authenticator as defined in config
	SetName(name string)

	// Returns name of authenticator
	GetName() string
}

type basicAuth struct {
	name string
}

func (a *basicAuth) SetName(name string) {
	a.name = name
}

func (a *basicAuth) GetName() string {
	return a.name
}
