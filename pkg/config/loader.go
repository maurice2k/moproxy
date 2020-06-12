// Copyright 2019-2020 Moritz Fain
// Moritz Fain <moritz@fain.io>
package config

import (
	"moproxy/internal/proxyconn"
	"moproxy/pkg/authenticator"

	"github.com/DisposaBoy/JsonConfigReader"
	"github.com/rs/zerolog/log"

	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type RootConfig struct {
	Listen  []interface{} `json:"listen"`
	Access  AccessConfig  `json:"access"`
	Timeout TimeoutConfig `json:"timeout"`
	Tuning  TuningConfig  `json:"tuning"`
	Stats   StatsConfig   `json:"stats"`
}

type AccessConfig struct {
	AuthRules  []interface{}         `json:"authRules"`
	ProxyRules []interface{}         `json:"proxyRules"`
	Auth       map[string]AuthConfig `json:"auth"`
}

type AuthRulesConfig struct {
	From     string `json:"from"`
	To       string `json:"to"`
	AuthName string `json:"authName"`
}

type ProxyRulesConfig struct {
	Type    string        `json:"type"`
	From    string        `json:"from"`
	To      string        `json:"to"`
	Via     string        `json:"via"`
	Timeout TimeoutConfig `json:"timeout"`
}

type AuthConfig struct {
	AuthType     string `json:"type"`
	Username     string `json:"username"`     // used for type static
	Password     string `json:"password"`     // used for type static
	Path         string `json:"path"`         // used for type binary
	MaxProcs     int    `json:"maxProcs"`     // used for type binary
	IdleProcs    int    `json:"idleProcs"`    // used for type binary
	StartupProcs int    `json:"startupProcs"` // used for type binary
}

type Duration int64

type TimeoutConfig struct {
	Tcp  TimeoutTcpConfig  `json:"tcp"`
	Http TimeoutHttpConfig `json:"http"`
}

type TimeoutTcpConfig struct {
	Connect   Duration `json:"connect"`
	KeepAlive Duration `json:"keepAlive"`
	Idle      Duration `json:"idle"`
	Negotiate Duration `json:"negotiate"`
}

type TimeoutHttpConfig struct {
	KeepAlive Duration `json:"keepAlive"`
}

type TuningConfig struct {
	TFOIncoming bool `json:"tfoIncoming"`
	TFOOutgoing bool `json:"tfoOutgoing"`
}

type StatsConfig struct {
	Enabled         bool            `json:"enabled"`
	Webserver       WebserverConfig `json:"webserver"`
	Resolution      int             `json:"resolution"`
	SplitByInternal bool            `json:"splitByInternal"`
	Retention       int             `json:"retention"`
	Db              string          `json:"db"`
}

type WebserverConfig struct {
	CertFile  string   `json:"certFile"`
	KeyFile   string   `json:"keyFile"`
	Listen    string   `json:"listen"`
	AllowFrom []string `json:"allowFrom"`
}

type ListenConfig struct {
	Type     string `json:"type"`
	Internal string `json:"internal"`
	External string `json:"external"`
}

func (d *Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(*d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch value := v.(type) {
	case float64:
		*d = Duration(time.Duration(value) * time.Second)
		return nil
	case string:
		duration, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(duration)
		return nil
	default:
		return errors.New("invalid duration")
	}
}

const AUTH_NONE = "none"
const (
	VIA_TYPE_NONE  = 0
	VIA_TYPE_PROXY = 1
	VIA_TYPE_AUTH  = 2
)

type listenMapType map[string]*ListenConfig

var configuration *RootConfig
var listenMap listenMapType = make(listenMapType)

var authenticatorMap = make(map[string]authenticator.Authenticator)

type authRule struct {
	authName string
	from     *net.IPNet
	to       *net.TCPAddr
}

type proxyRule struct {
	allow    bool
	from     *net.IPNet
	viaType  int
	viaProxy *net.TCPAddr
	viaAuth  string
	to       *net.IPNet
}

var authRules []authRule
var proxyRules []proxyRule

// Loads configuration and does some basic validation (i.e. not empty checks, format checks, file/dir exists)
// Final validation is done by the package that uses the configuration
func LoadConfig(path string) (*RootConfig, error) {
	// Default values
	configuration = &RootConfig{
		Timeout: TimeoutConfig{
			Tcp: TimeoutTcpConfig{
				Connect:   Duration(30 * time.Second),
				KeepAlive: Duration(30 * time.Second),
				Idle:      Duration(90 * time.Second),
				Negotiate: Duration(30 * time.Second),
			},
		},
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open config file: %s", path)
	}
	defer file.Close()

	jsonConfig := JsonConfigReader.New(file)

	err = json.NewDecoder(jsonConfig).Decode(configuration)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %s", err)
	}

	// Parse listen IP addresses
	for _, listen := range configuration.Listen {

		reStrRule := regexp.MustCompile("(socks5|http)\\s+(\\S+)(?:\\s+(\\S+))?")

		switch ipOrStruct := listen.(type) {
		case string:
			matches := reStrRule.FindStringSubmatch(ipOrStruct)
			if len(matches) != 4 {
				return nil, fmt.Errorf("listen config string has an invalid format: '%s'", ipOrStruct)
			}

			if matches[1] != "socks5" && matches[1] != "http" {
				return nil, fmt.Errorf("listen config string has an invalid server type: '%s'", matches[1])
			}

			lc := ListenConfig{
				Type:     matches[1],
				Internal: matches[2],
				External: matches[3],
			}

			if err := addToListenMap(&lc); err != nil {
				return nil, err
			}
		case map[string]interface{}:
			var lc ListenConfig
			tmpBytes, _ := json.Marshal(ipOrStruct)
			json.Unmarshal(tmpBytes, &lc)

			if err := addToListenMap(&lc); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("'%v' is not a valid IP address", ipOrStruct)
		}

	}

	// Parse auth rules and add authenticator to lookup
	for _, rule := range configuration.Access.AuthRules {

		var ruleConfig AuthRulesConfig
		var fromIPNet *net.IPNet
		var toIPPort *net.TCPAddr
		reStrRule := regexp.MustCompile("^(?:auth\\s+with\\s+)?(\\S+)\\s+from\\s+(\\S+)\\s+to\\s+(\\S+)")

		switch stringOrStruct := rule.(type) {
		case string:
			matches := reStrRule.FindStringSubmatch(stringOrStruct)
			if len(matches) != 4 {
				return nil, fmt.Errorf("auth rule string has an invalid format: '%s'", stringOrStruct)
			}

			ruleConfig.AuthName = matches[1]
			ruleConfig.From = matches[2]
			ruleConfig.To = matches[3]

		case map[string]interface{}:
			tmpBytes, _ := json.Marshal(stringOrStruct)
			json.Unmarshal(tmpBytes, &ruleConfig)
		}

		if ruleConfig.AuthName == "" {
			return nil, fmt.Errorf("auth rule with missing authenticator")
		}

		if ruleConfig.AuthName != AUTH_NONE {
			authConfig, exists := configuration.Access.Auth[ruleConfig.AuthName]
			if !exists {
				return nil, fmt.Errorf("auth rule with unknown authenticator: '%s'", ruleConfig.AuthName)
			}

			if _, exists := authenticatorMap[ruleConfig.AuthName]; !exists {

				switch authConfig.AuthType {
				case "static":
					if authConfig.Username == "" {
						return nil, fmt.Errorf("%s authenticator '%s' must have a username set", authConfig.AuthType, ruleConfig.AuthName)
					}
					if authConfig.Password == "" {
						return nil, fmt.Errorf("%s authenticator '%s' must have a password set", authConfig.AuthType, ruleConfig.AuthName)
					}

					authenticatorMap[ruleConfig.AuthName] = authenticator.NewStaticAuth(authConfig.Username, authConfig.Password)

				default:
					return nil, fmt.Errorf("authenticator '%s' has an invalid type: '%s'", ruleConfig.AuthName, authConfig.AuthType)
				}

			}
		}

		if ruleConfig.From == "all" || ruleConfig.From == "any" {
			fromIPNet = nil
		} else {
			fromIPNet, err = ParseCIDR(ruleConfig.From)
			if err != nil {
				return nil, fmt.Errorf("auth rule from '%s' is not a valid IP address", ruleConfig.From)
			}
		}

		if ruleConfig.To == "all" || ruleConfig.To == "any" {
			toIPPort = nil
		} else {

			host, portStr, err := net.SplitHostPort(ruleConfig.To)
			if err != nil {
				return nil, fmt.Errorf("auth rule to '%s': not a valid IPv4:port or [IPv6]:port address", ruleConfig.To)
			}

			ip := net.ParseIP(host)
			if ip == nil {
				return nil, fmt.Errorf("auth rule to '%s': '%s' is not a valid IPv4 or IPv6 address", ruleConfig.To, ruleConfig.To)
			}

			port, err := strconv.Atoi(portStr)
			if err != nil || port < 0 || port > 65535 {
				return nil, fmt.Errorf("auth rule to '%s': '%s' is not a valid TCP port", ruleConfig.To, portStr)
			}

			toIPPort = &net.TCPAddr{
				IP:   ip,
				Port: port,
			}
		}

		authRules = append(authRules, authRule{
			authName: ruleConfig.AuthName,
			from:     fromIPNet,
			to:       toIPPort,
		})

	}

	// Parse proxy rules
	for _, rule := range configuration.Access.ProxyRules {

		var ruleConfig ProxyRulesConfig
		var fromIPNet, toIPNet *net.IPNet
		var allow bool
		reStrRule := regexp.MustCompile("^(allow|deny)\\s+from\\s+(\\S+)\\s+(?:via\\s+(\\S+)\\s+)?to\\s+(\\S+)")

		switch stringOrStruct := rule.(type) {
		case string:
			matches := reStrRule.FindStringSubmatch(stringOrStruct)
			if len(matches) != 5 {
				return nil, fmt.Errorf("proxy rule string has an invalid format: '%s'", stringOrStruct)
			}

			ruleConfig.Type = matches[1]
			ruleConfig.From = matches[2]
			ruleConfig.Via = matches[3]
			ruleConfig.To = matches[4]

		case map[string]interface{}:
			tmpBytes, _ := json.Marshal(stringOrStruct)
			json.Unmarshal(tmpBytes, &ruleConfig)
		}

		allow = ruleConfig.Type == "allow"

		if ruleConfig.From == "all" || ruleConfig.From == "any" {
			fromIPNet = nil
		} else {
			fromIPNet, err = ParseCIDR(ruleConfig.From)
			if err != nil {
				return nil, fmt.Errorf("proxy rule from '%s' is not a valid IP address or range", ruleConfig.From)
			}
		}

		if ruleConfig.To == "all" || ruleConfig.To == "any" {
			toIPNet = nil
		} else {
			toIPNet, err = ParseCIDR(ruleConfig.To)
			if err != nil {
				return nil, fmt.Errorf("proxy rule to '%s' is not a valid IP address or range", ruleConfig.From)
			}
		}

		// parse via if set
		var viaType int = VIA_TYPE_NONE
		var viaProxy *net.TCPAddr = nil
		var viaAuth string = ""

		if ruleConfig.Via != "all" && ruleConfig.Via != "" {
			host, portStr, err := net.SplitHostPort(ruleConfig.Via)
			if err == nil {

				ip := net.ParseIP(host)
				if ip == nil {
					return nil, fmt.Errorf("proxy rule via '%s' is not a valid IPv4 or IPv6 address", ruleConfig.Via)
				}

				port, err := strconv.Atoi(portStr)
				if err != nil || port < 0 || port > 65535 {
					return nil, fmt.Errorf("proxy rule via '%s': '%s' is not a valid TCP port", ruleConfig.Via, portStr)
				}

				viaType = VIA_TYPE_PROXY
				viaProxy = &net.TCPAddr{
					IP:   ip,
					Port: port,
				}

			} else {
				// does not look like host:port; assume it's an authenticator name

				if ruleConfig.Via != AUTH_NONE {
					if _, exists := authenticatorMap[ruleConfig.Via]; !exists {
						return nil, fmt.Errorf("proxy rule via '%s': '%s' is neither a valid TCP port nor a valid authenicator name", ruleConfig.Via, ruleConfig.Via)
					}
				}

				viaType = VIA_TYPE_AUTH
				viaAuth = ruleConfig.Via
			}
		}

		proxyRules = append(proxyRules, proxyRule{
			allow:    allow,
			from:     fromIPNet,
			viaType:  viaType,
			viaProxy: viaProxy,
			viaAuth:  viaAuth,
			to:       toIPNet,
		})

	}

	// Stats
	if configuration.Stats.Enabled {

		if configuration.Stats.Webserver.Listen != "" {
			// looks like we want a webserver

			if configuration.Stats.Webserver.CertFile != "" && configuration.Stats.Webserver.KeyFile == "" {
				return nil, fmt.Errorf("stats.webserver.keyFile must not be empty")
			}

			if configuration.Stats.Webserver.KeyFile != "" && configuration.Stats.Webserver.CertFile == "" {
				return nil, fmt.Errorf("stats.webserver.certFile must not be empty")
			}

			if configuration.Stats.Webserver.CertFile != "" {
			}

		}

	}

	confbytes, _ := json.Marshal(configuration)
	log.Debug().Msgf("Loaded configuration: %s", string(confbytes))

	return configuration, nil
}

func GetStatsConfig() StatsConfig {
	return configuration.Stats
}

// Returns listening map
func GetListenMap() listenMapType {
	return listenMap
}

// Returns TCP timeout configuration
func GetTcpTimeouts() TimeoutTcpConfig {
	return configuration.Timeout.Tcp
}

// Returns HTTP timeout configuration
func GetHttpTimeouts() TimeoutHttpConfig {
	return configuration.Timeout.Http
}

// Returns tuning configuration
func GetTuningConfig() TuningConfig {
	return configuration.Tuning
}

// Checks whether we should accept and incoming TCP connection from the given IP
func IsClientConnectionAllowed(proxyConn *proxyconn.ProxyConn) bool {
	from := proxyConn.GetClientAddr().IP
	proxy := proxyConn.GetInternalAddr()
	for _, rule := range proxyRules {
		if rule.viaType == VIA_TYPE_AUTH {
			// no info on authentication in this stage; ignore rule
			continue
		}

		if rule.viaType == VIA_TYPE_PROXY {
			// rule does only apply for a given proxy
			if !((rule.viaProxy.IP.IsUnspecified() || rule.viaProxy.IP.Equal(proxy.IP)) && (rule.viaProxy.Port == 0 || rule.viaProxy.Port == proxy.Port)) {
				// does not match; ignore
				continue
			}
		}

		if rule.from == nil || rule.from.Contains(from) {

			if rule.allow {
				// the client is at least allowed to connect to some remote destination
				return true

			} else {
				if rule.to == nil {
					// all connections to any remote destination are denied, so we disallow that client completely
					return false
				} else {
					// the client is not allowed to connect to some remote destination but we don't know the
					// remote destination at this stage yet. skip the rule.
					continue
				}

			}
		}
	}

	return false
}

// Client needs auth?
func IsClientAuthRequired(proxyConn *proxyconn.ProxyConn) (required bool, authenticator authenticator.Authenticator, authName string) {
	from := proxyConn.GetClientAddr().IP
	to := proxyConn.GetInternalAddr()
	for _, rule := range authRules {
		if rule.from == nil || rule.from.Contains(from) {
			if rule.to == nil ||
				(rule.to.IP.IsUnspecified() || rule.to.IP.Equal(to.IP)) && (rule.to.Port == 0 || rule.to.Port == to.Port) {
				if rule.authName == AUTH_NONE {
					return false, nil, ""
				}
				return true, authenticatorMap[rule.authName], rule.authName
			}
		}
	}

	return false, nil, ""
}

// Checks whether we should accept a proxy request from IP <from> to IP <to>
func IsProxyConnectionAllowed(proxyConn *proxyconn.ProxyConn, to net.IP) bool {
	from := proxyConn.GetClientAddr().IP
	proxy := proxyConn.GetInternalAddr()
	for _, rule := range proxyRules {
		if rule.viaType == VIA_TYPE_PROXY {
			if !((rule.viaProxy.IP.IsUnspecified() || rule.viaProxy.IP.Equal(proxy.IP)) && (rule.viaProxy.Port == 0 || rule.viaProxy.Port == proxy.Port)) {
				continue
			}
		} else if rule.viaType == VIA_TYPE_AUTH {
			authed, authName := proxyConn.IsSuccessfullyAuthenticated()
			if !authed && rule.viaAuth != AUTH_NONE || authed && rule.viaAuth != authName {
				continue
			}
		}

		if rule.from == nil || rule.from.Contains(from) {
			if rule.to == nil || rule.to.Contains(to) {
				return rule.allow
			}
		}
	}

	return false
}

// Parses CIDR IP ranges
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

func addToListenMap(lc *ListenConfig) error {
	intIp, _, err := net.SplitHostPort(lc.Internal)
	if err != nil {
		return err
	}

	if net.ParseIP(intIp) == nil {
		return fmt.Errorf("address %s: not a valid IPv4 or IPv6 address", intIp)
	}

	if lc.External == "" {
		lc.External = intIp
	}

	if net.ParseIP(lc.External) == nil {
		return fmt.Errorf("address %s: not a valid IPv4 or IPv6 address", lc.External)
	}

	listenMap[lc.Type+"-"+lc.Internal] = lc
	return nil
}
