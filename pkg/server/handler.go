// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package server

import (
	"moproxy/pkg/config"
	"moproxy/pkg/server/httpproxy"
	"moproxy/pkg/server/socks5proxy"
	"moproxy/pkg/server/stats"

	"github.com/rs/zerolog/log"

	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

var stopChan chan os.Signal
var reloadChan chan os.Signal

type serverSet struct {
	socks5ProxyServers []*socks5proxy.Server
	httpProxyServers   []*httpproxy.Server
	statsServer        *stats.Server
	stopChan           chan os.Signal
	stopped            bool
}

var mutex sync.Mutex

var wg sync.WaitGroup

var currentServerSet *serverSet
var err error

func Run(getConfig func() *config.Configuration) error {

	stopChan = make(chan os.Signal, 0)
	reloadChan = make(chan os.Signal, 0)

	// Subscribe to signals
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(reloadChan, syscall.SIGHUP)

	go func() {
		// wait for SIGHUP
		for {
			<-reloadChan
			log.Info().Msgf("Received SIGHUP; gracefully restarting all services")

			mutex.Lock()
			serverSet, err := startServers(getConfig(), &wg)
			currentServerSet.stopServers()

			if err != nil {
				if serverSet != nil {
					serverSet.stopServers()
				}
			} else {
				currentServerSet = serverSet
			}
			mutex.Unlock()
		}
	}()

	mutex.Lock()
	currentServerSet, err = startServers(getConfig(), &wg)
	mutex.Unlock()
	if err != nil {
		return err
	}

	go func() {
		// wait for SIGINT, SIGTERM
		<-stopChan
		mutex.Lock()
		currentServerSet.stopServers()
		mutex.Unlock()
	}()

	wg.Wait()

	return nil
}

func startServers(configInstance *config.Configuration, wg *sync.WaitGroup) (*serverSet, error) {

	serverSet := &serverSet{
		stopChan: make(chan os.Signal, 0),
	}

	for _, lc := range configInstance.GetListenMap() {
		if lc.Type == "socks5" {
			server := socks5proxy.NewServer(lc.Internal, lc.External, configInstance)
			log := log.With().Str("instance", fmt.Sprintf("%p", server)).Logger()

			err := server.Listen()
			if err != nil {
				log.Warn().Msgf("Unable to setup listening SOCKS5 on '%s': %s", lc.Internal, err.Error())
				continue
			}

			serverSet.socks5ProxyServers = append(serverSet.socks5ProxyServers, server)
			wg.Add(1)
			go func(lc *config.ListenConfig) {
				log.Info().Msgf("Listen and serving SOCKS5 on '%s' ==> '%s'", lc.Internal, lc.External)
				err := server.Serve()
				if err != nil {
					log.Error().Msgf("Stopped serving SOCKS5 on '%s' ==> '%s'", lc.Internal, lc.External)
				}
				wg.Done()
			}(lc)

		} else if lc.Type == "http" {

			server := httpproxy.NewServer(lc.Internal, lc.External, configInstance)
			log := log.With().Str("instance", fmt.Sprintf("%p", server)).Logger()

			err := server.Listen()
			if err != nil {

				log.Warn().Msgf("Unable to setup listening HTTP on '%s': %s", lc.Internal, err.Error())
				continue
			}

			serverSet.httpProxyServers = append(serverSet.httpProxyServers, server)
			wg.Add(1)
			go func(lc *config.ListenConfig) {
				log.Info().Msgf("Listen and serving HTTP on '%s' ==> '%s'", lc.Internal, lc.External)
				err := server.Serve()
				if err != nil {
					log.Error().Msgf("Stopped serving HTTP on '%s' ==> '%s'", lc.Internal, lc.External)
				}
				wg.Done()
			}(lc)

		}
	}

	if len(serverSet.socks5ProxyServers) == 0 && len(serverSet.httpProxyServers) == 0 {
		return nil, fmt.Errorf("not able to listen on any configured IP:port tuple")
	}

	if serverSet.statsServer = stats.CreateStatsServer(configInstance.GetStatsConfig()); serverSet.statsServer != nil {
		log := log.With().Str("instance", fmt.Sprintf("%p", serverSet.statsServer)).Logger()
		wg.Add(1)
		go func() {
			log.Info().Msgf("Listen and serving stats on '%s'", serverSet.statsServer.Addr)
			err := serverSet.statsServer.Serve()
			if err != nil {
				log.Error().Msgf("Error running stats web server: %s", err)
			}
			wg.Done()
		}()
	}

	return serverSet, nil
}

func (serverSet *serverSet) stopServers() {
	if serverSet.stopped {
		return
	}

	log.Info().Msg("Shutting down socks server gracefully...")

	for _, server := range serverSet.socks5ProxyServers {
		log.Info().Str("instance", fmt.Sprintf("%p", server)).Msgf("Stop listening for SOCKS5 on %s", server.GetListenAddr())
		server.Shutdown(10 * time.Second)
	}

	for _, server := range serverSet.httpProxyServers {
		log.Info().Str("instance", fmt.Sprintf("%p", server)).Msgf("Stop listening for HTTP on %s", server.GetListenAddr())
		server.Shutdown(10 * time.Second)
	}

	if serverSet.statsServer != nil {
		log.Info().Str("instance", fmt.Sprintf("%p", serverSet.statsServer)).Msg("Shutting down stats web server gracefully...")
		// shut down gracefully, but wait no longer than 1 seconds before halting
		ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
		serverSet.statsServer.Shutdown(ctx)
	}

	serverSet.stopped = true
}
