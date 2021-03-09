// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package config

import (
	"moproxy/internal/proxyconn"
	"moproxy/pkg/auth"
	"moproxy/pkg/misc"

	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/DisposaBoy/JsonConfigReader"
	"github.com/maurice2k/tcpserver"
	"github.com/rs/zerolog/log"
)

type RootConfig struct {
	Listen  []interface{} `json:"listen"`
	Access  AccessConfig  `json:"access"`
	Timeout TimeoutConfig `json:"timeout"`
	Tuning  TuningConfig  `json:"tuning"`
	Stats   StatsConfig   `json:"stats"`
}

type AccessConfig struct {
	ClientRules []interface{}         `json:"clientRules"`
	ProxyRules  []interface{}         `json:"proxyRules"`
	Auth        map[string]AuthConfig `json:"auth"`
}

type AuthRulesConfig struct {
	Type     string `json:"type"`
	From     string `json:"from"`
	To       string `json:"to"`
	AuthName string `json:"withAuth"`
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

const AuthNone = "none"
const (
	ViaTypeNone  = 0
	ViaTypeProxy = 1
	ViaTypeAuth  = 2
)

const (
	ProxyTypeUnspecified = 0
	ProxyTypeSocks5      = 1
	ProxyTypeHttp        = 2
)

type clientRule struct {
	allow       bool
	authName    string
	from        *net.IPNet
	to          *net.TCPAddr
	toProxyType int
}

type proxyRule struct {
	allow       bool
	from        *net.IPNet
	viaType     int
	viaProxy    *net.TCPAddr
	viaAuthName string
	to          *net.IPNet
}

type listenMapType map[string]*ListenConfig
type authenticatorMapType map[string]auth.Authenticator

type Configuration struct {
	root             *RootConfig
	listenMap        listenMapType
	authenticatorMap authenticatorMapType
	clientRules      []clientRule
	proxyRules       []proxyRule
}

// LoadConfig loads configuration and does some basic validation (i.e. not empty checks, format checks, file/dir exists)
// Final validation is done by the package that uses the configuration
func LoadConfig(path string) (*Configuration, error) {

	// Default values
	mainConf := &RootConfig{
		Timeout: TimeoutConfig{
			Tcp: TimeoutTcpConfig{
				Connect:   Duration(30 * time.Second),
				KeepAlive: Duration(30 * time.Second),
				Idle:      Duration(90 * time.Second),
				Negotiate: Duration(30 * time.Second),
			},
		},
	}

	configInstance := &Configuration{
		root:             mainConf,
		listenMap:        make(listenMapType),
		authenticatorMap: make(authenticatorMapType),
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open config file: %s", path)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	jsonConfig := JsonConfigReader.New(file)

	err = json.NewDecoder(jsonConfig).Decode(mainConf)
	if err != nil {
		return nil, fmt.Errorf("error parsing config file: %s", err)
	}

	// Parse listen IP addresses
	for _, listen := range mainConf.Listen {

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

			if err := configInstance.addToListenMap(&lc); err != nil {
				return nil, err
			}
		case map[string]interface{}:
			var lc ListenConfig
			tmpBytes, _ := json.Marshal(ipOrStruct)
			_ = json.Unmarshal(tmpBytes, &lc)

			if err := configInstance.addToListenMap(&lc); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("'%v' is not a valid IP address", ipOrStruct)
		}

	}

	// Parse client rules and add authenticator to lookup
	for _, rule := range mainConf.Access.ClientRules {

		var ruleConfig AuthRulesConfig
		var fromIPNet *net.IPNet
		var toIPPort *net.TCPAddr
		var toProxyType int
		reStrRule := regexp.MustCompile("^(allow|deny)\\s+from\\s+(\\S+)\\s+to\\s+(\\S+)(?:\\s+with.auth\\s(\\S+)|)$")

		switch stringOrStruct := rule.(type) {
		case string:
			matches := reStrRule.FindStringSubmatch(stringOrStruct)
			if len(matches) != 5 {
				return nil, fmt.Errorf("client rule string has an invalid format: '%s'", stringOrStruct)
			}

			ruleConfig.Type = matches[1]
			ruleConfig.AuthName = matches[4]
			ruleConfig.From = matches[2]
			ruleConfig.To = matches[3]

		case map[string]interface{}:
			tmpBytes, _ := json.Marshal(stringOrStruct)
			_ = json.Unmarshal(tmpBytes, &ruleConfig)
		}

		if ruleConfig.Type != "allow" && ruleConfig.Type != "deny" {
			return nil, fmt.Errorf("client rule type must be either 'allow' or 'deny', given: '%s'", ruleConfig.Type)
		}

		if ruleConfig.AuthName != AuthNone && ruleConfig.AuthName != "" {
			authConfig, exists := mainConf.Access.Auth[ruleConfig.AuthName]
			if !exists {
				return nil, fmt.Errorf("client rule with unknown authenticator: '%s'", ruleConfig.AuthName)
			}

			if _, exists := configInstance.authenticatorMap[ruleConfig.AuthName]; !exists {

				var authenticator auth.Authenticator

				switch authConfig.AuthType {
				case "static":
					if authConfig.Username == "" {
						return nil, fmt.Errorf("%s authenticator '%s' must have a username set", authConfig.AuthType, ruleConfig.AuthName)
					}
					if authConfig.Password == "" {
						return nil, fmt.Errorf("%s authenticator '%s' must have a password set", authConfig.AuthType, ruleConfig.AuthName)
					}

					authenticator = auth.NewStaticAuth(authConfig.Username, authConfig.Password)

				default:
					return nil, fmt.Errorf("authenticator '%s' has an invalid type: '%s'", ruleConfig.AuthName, authConfig.AuthType)
				}

				authenticator.SetName(ruleConfig.AuthName)
				configInstance.authenticatorMap[ruleConfig.AuthName] = authenticator
			}
		}

		if ruleConfig.From == "all" || ruleConfig.From == "any" {
			fromIPNet = nil
		} else {
			fromIPNet, err = misc.ParseCIDR(ruleConfig.From)
			if err != nil {
				return nil, fmt.Errorf("client rule from '%s' is not a valid IP address", ruleConfig.From)
			}
		}

		if ruleConfig.To == "all" || ruleConfig.To == "any" {
			toIPPort = nil
		} else if ruleConfig.To == "socks5" {
			toProxyType = ProxyTypeSocks5
			toIPPort = nil
		} else if ruleConfig.To == "http" {
			toProxyType = ProxyTypeHttp
			toIPPort = nil
		} else {

			host, portStr, err := net.SplitHostPort(ruleConfig.To)
			if err != nil {
				return nil, fmt.Errorf("client rule to '%s': not a valid IPv4:port or [IPv6]:port address", ruleConfig.To)
			}

			ip := net.ParseIP(host)
			if ip == nil {
				return nil, fmt.Errorf("client rule to '%s': '%s' is not a valid IPv4 or IPv6 address", ruleConfig.To, ruleConfig.To)
			}

			port, err := strconv.Atoi(portStr)
			if err != nil || port < 0 || port > 65535 {
				return nil, fmt.Errorf("client rule to '%s': '%s' is not a valid TCP port", ruleConfig.To, portStr)
			}

			toIPPort = &net.TCPAddr{
				IP:   ip,
				Port: port,
			}
		}

		configInstance.clientRules = append(configInstance.clientRules, clientRule{
			allow:       ruleConfig.Type == "allow",
			authName:    ruleConfig.AuthName,
			from:        fromIPNet,
			to:          toIPPort,
			toProxyType: toProxyType,
		})

	}

	// Parse proxy rules
	for _, rule := range mainConf.Access.ProxyRules {

		var ruleConfig ProxyRulesConfig
		var fromIPNet, toIPNet *net.IPNet
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
			_ = json.Unmarshal(tmpBytes, &ruleConfig)
		}

		if ruleConfig.Type != "allow" && ruleConfig.Type != "deny" {
			return nil, fmt.Errorf("proxy rule type must be either 'allow' or 'deny', given: '%s'", ruleConfig.Type)
		}

		if ruleConfig.From == "all" || ruleConfig.From == "any" {
			fromIPNet = nil
		} else {
			fromIPNet, err = misc.ParseCIDR(ruleConfig.From)
			if err != nil {
				return nil, fmt.Errorf("proxy rule from '%s' is not a valid IP address or range", ruleConfig.From)
			}
		}

		if ruleConfig.To == "all" || ruleConfig.To == "any" {
			toIPNet = nil
		} else {
			toIPNet, err = misc.ParseCIDR(ruleConfig.To)
			if err != nil {
				return nil, fmt.Errorf("proxy rule to '%s' is not a valid IP address or range", ruleConfig.From)
			}
		}

		// parse via if set
		var viaType = ViaTypeNone
		var viaProxy *net.TCPAddr = nil
		var viaAuth = ""

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

				viaType = ViaTypeProxy
				viaProxy = &net.TCPAddr{
					IP:   ip,
					Port: port,
				}

			} else {
				// does not look like host:port; assume it's an authenticator name

				if ruleConfig.Via != AuthNone {
					if _, exists := configInstance.authenticatorMap[ruleConfig.Via]; !exists {
						return nil, fmt.Errorf("proxy rule via '%s': '%s' is neither a valid TCP port nor a valid authenicator name", ruleConfig.Via, ruleConfig.Via)
					}
				}

				viaType = ViaTypeAuth
				viaAuth = ruleConfig.Via
			}
		}

		configInstance.proxyRules = append(configInstance.proxyRules, proxyRule{
			allow:       ruleConfig.Type == "allow",
			from:        fromIPNet,
			viaType:     viaType,
			viaProxy:    viaProxy,
			viaAuthName: viaAuth,
			to:          toIPNet,
		})

	}

	// Stats
	if mainConf.Stats.Enabled {

		if mainConf.Stats.Webserver.Listen != "" {
			// looks like we want a webserver

			if mainConf.Stats.Webserver.CertFile != "" && mainConf.Stats.Webserver.KeyFile == "" {
				return nil, fmt.Errorf("stats.webserver.keyFile must not be empty")
			}

			if mainConf.Stats.Webserver.KeyFile != "" && mainConf.Stats.Webserver.CertFile == "" {
				return nil, fmt.Errorf("stats.webserver.certFile must not be empty")
			}

			if mainConf.Stats.Webserver.CertFile != "" {
			}

		}

	}

	confbytes, _ := json.Marshal(mainConf)
	log.Debug().Msgf("Loaded configuration: %s", string(confbytes))

	return configInstance, nil
}

func (ci *Configuration) GetStatsConfig() StatsConfig {
	return ci.root.Stats
}

// GetListenMap returns the listening map
//goland:noinspection GoExportedFuncWithUnexportedType
func (ci *Configuration) GetListenMap() listenMapType {
	return ci.listenMap
}

// GetTcpTimeouts returns TCP timeout configuration
func (ci *Configuration) GetTcpTimeouts() TimeoutTcpConfig {
	return ci.root.Timeout.Tcp
}

// GetHttpTimeouts returns HTTP timeout configuration
func (ci *Configuration) GetHttpTimeouts() TimeoutHttpConfig {
	return ci.root.Timeout.Http
}

// GetTuningConfig returns tuning configuration
func (ci *Configuration) GetTuningConfig() TuningConfig {
	return ci.root.Tuning
}

func (ci *Configuration) addToListenMap(lc *ListenConfig) error {
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

	ci.listenMap[lc.Type+"-"+lc.Internal] = lc
	return nil
}

// IsClientConnectionAllowed checks whether we should accept an incoming TCP connection
// If allowed == true, the returned authenticator (!= nil) must be checked
func (ci *Configuration) IsClientConnectionAllowed(conn *proxyconn.ProxyConn) (allowed bool, authenticator auth.Authenticator) {
	from := conn.GetClientAddr().IP
	toProxyInternal := conn.GetInternalAddr()
	toProxyType := conn.GetProxyType()
	for _, rule := range ci.clientRules {
		if rule.from == nil || rule.from.Contains(from) {
			if rule.to == nil && rule.toProxyType == ProxyTypeUnspecified || // "... to all"
				rule.to == nil && rule.toProxyType != ProxyTypeUnspecified && rule.toProxyType == toProxyType || // "... to socks5|http"
				rule.to != nil && (rule.to.IP.IsUnspecified() || rule.to.IP.Equal(toProxyInternal.IP)) && (rule.to.Port == 0 || rule.to.Port == toProxyInternal.Port) { // "... to <ip>:<port>"

				if rule.allow {
					if rule.authName == AuthNone {
						return true, nil
					}
					return true, ci.authenticatorMap[rule.authName]
				} else {
					break
				}
			}
		}
	}
	return false, nil
}

// IsProxyConnectionAllowed checks whether we should accept a proxy request from <fromIP> via <auth|internalIP> to <toIP>
func (ci *Configuration) IsProxyConnectionAllowed(conn *proxyconn.ProxyConn, to net.IP) bool {
	from := conn.GetClientAddr().IP
	authenticated, authenticator := conn.IsSuccessfullyAuthenticated()
	proxyInternal := conn.GetInternalAddr()

	for _, rule := range ci.proxyRules {
		if rule.viaType == ViaTypeProxy {
			if !((rule.viaProxy.IP.IsUnspecified() || rule.viaProxy.IP.Equal(proxyInternal.IP)) && (rule.viaProxy.Port == 0 || rule.viaProxy.Port == proxyInternal.Port)) {
				continue
			}
		} else if rule.viaType == ViaTypeAuth {
			if !authenticated && rule.viaAuthName != AuthNone || authenticated && rule.viaAuthName != authenticator.GetName() {
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

func GetForServer(s *tcpserver.Server) *Configuration {
	return (*s.GetContext()).Value(proxyconn.CtxKey("config")).(*Configuration)
}
