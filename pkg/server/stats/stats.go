// Copyright 2019-2020 Moritz Fain
// Moritz Fain <moritz@fain.io>
package stats

//// EARLY DRAFT ////

import (
	"moproxy/pkg/config"

	"github.com/gorilla/mux"
	om "github.com/maurice2k/orderedmap"

	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"time"
)

type Server struct {
	*http.Server
	config config.WebserverConfig
}

func CreateStatsServer() *Server {
	statsConfig := config.GetStatsConfig()
	if statsConfig.Webserver.Listen == "" {
		return nil
	}

	statsServer := new(Server)
	statsServer.config = statsConfig.Webserver

	r := mux.NewRouter()
	r.HandleFunc("/stats", handleStats)

	statsServer.Server = &http.Server{
		Addr:    statsConfig.Webserver.Listen,
		Handler: http.Handler(r),
	}

	if statsServer.config.CertFile != "" {
		statsServer.TLSConfig = &tls.Config{
			MinVersion:               tls.VersionTLS12,
			MaxVersion:               tls.VersionTLS13,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_FALLBACK_SCSV,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			ClientAuth: tls.RequestClientCert,
		}
	}

	return statsServer
}

// start serving
func (server *Server) Serve() (err error) {
	// start the actual listener
	if server.TLSConfig != nil {
		err = server.ListenAndServeTLS(server.config.CertFile, server.config.KeyFile)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		return
	}

	return nil
}

func handleStats(w http.ResponseWriter, req *http.Request) {
	//if (!isRestrictedAccessAllowed(req)) {
	//    createJsonResponse(w, req, 403, nil, "")
	//    return
	//}

	response := om.NewOrderedMap()

	createJsonResponse(w, req, 200, response, "")

}

// Creates and sends formatted json response
func createJsonResponse(w http.ResponseWriter, req *http.Request, statusCode int, data *om.OrderedMap, error string) {
	if statusCode == 0 {
		statusCode = 200
	}

	success := true
	if statusCode < 200 || statusCode > 299 {
		success = false
	}

	w.Header().Set("Content-authType", "application/json")
	w.WriteHeader(statusCode)

	status := om.NewOrderedMap(
		&om.KV{Key: "http", Value: om.NewOrderedMap(
			&om.KV{Key: "code", Value: statusCode},
			&om.KV{Key: "message", Value: http.StatusText(statusCode)},
		)})

	if error != "" {
		status.Set("error", error)
	}

	response := om.NewOrderedMap().
		Set("success", success).
		Set("status", status)

	if data != nil {
		response.Append(data, false)
	}

	jsonData, _ := json.Marshal(response)
	w.Write(jsonData)
}

type Event struct {
	ClientAddr,
	ExternalAddr,
	InternalAddr,
	RemoteAddr *net.TCPAddr
	SocksCommand,
	SocksReplyCode byte
	BytesWritten,
	BytesRead int64
	Elapsed time.Duration
}

type eventList []*Event

type key [20]byte

var eventChan chan Event

func init() {
	eventChan = make(chan Event, 10000)
	go SyncEvents()
}

func PushEvent(event Event) {
	eventChan <- event
}

func SyncEvents() {

	for {
		eventMap := make(map[key]eventList, 1000)
		count := 0
		timeout := time.After(time.Second * 30)

	SelectLoop:
		select {
		case event := <-eventChan:
			k := key{}
			copy(k[0:16], event.InternalAddr.IP.To16())
			k[16] = uint8(event.InternalAddr.Port >> 8)
			k[17] = uint8(event.InternalAddr.Port & 0x00ff)
			k[18] = event.SocksCommand
			k[19] = event.SocksReplyCode

			_, exists := eventMap[k]
			if !exists {
				eventMap[k] = eventList{&event}
			} else {
				eventMap[k] = append(eventMap[k], &event)
			}

			count++
			if count >= 10 {
				break
			}
			goto SelectLoop
		case <-timeout:
			break
		}

		//for k, v := range eventMap {
		//	fmt.Printf("%+v ===> %d\n\n", k, len(v))
		//}
	}

}
