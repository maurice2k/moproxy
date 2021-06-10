// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package misc

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// IsTimeoutError checks whether an error is a timeout "OpError"
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

// ParseCIDR parses CIDR IP ranges
func ParseCIDR(cidr string) (*net.IPNet, error) {
	if strings.Index(cidr, "/") == -1 {
		ip := net.ParseIP(cidr)
		if ip == nil {
			return nil, fmt.Errorf("%s is not a valid IP or CIDR range", cidr)
		}
		if strings.Index(cidr, ".") > -1 { // IPv4
			cidr += "/32"
		} else {
			cidr += "/128"
		}
	}
	_, net, err := net.ParseCIDR(cidr)

	if err != nil {
		return nil, err
	}

	return net, nil
}

// ParseTCPAddr parses TCP addresses
func ParseTCPAddr(tcpAddr string) (*net.TCPAddr, error) {
	host, portStr, err := net.SplitHostPort(tcpAddr)
	if err != nil {
		return nil, fmt.Errorf("not a valid IPv4:port or [IPv6]:port address")
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("'%s' is not a valid IPv4 or IPv6 address", host)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("'%s' is not a valid TCP port", portStr)
	}

	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}, nil
}
