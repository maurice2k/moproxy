// Copyright 2019-2020 Moritz Fain
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

var stopChan = make(chan os.Signal, 0)
var socks5ProxyServers []*socks5proxy.Server
var httpProxyServers []*httpproxy.Server
var statsServer *stats.Server
var serverWG sync.WaitGroup

func Run() error {

	// Subscribe to signals
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	go func() {
		// wait for SIGINT, SIGHUP, SIGTERM
		<-stopChan

		log.Info().Msg("Shutting down socks server gracefully...")

		for _, server := range socks5ProxyServers {
			server.Shutdown(10 * time.Second)
		}

		for _, server := range httpProxyServers {
			server.Shutdown(10 * time.Second)
		}

		if statsServer != nil {
			log.Info().Msg("Shutting down stats web server gracefully...")
			// shut down gracefully, but wait no longer than 1 seconds before halting
			ctx, _ := context.WithTimeout(context.Background(), 1*time.Second)
			statsServer.Shutdown(ctx)
		}

	}()

	for _, lc := range config.GetListenMap() {
		if lc.Type == "socks5" {
			server := socks5proxy.NewServer(lc.Internal, lc.External)
			err := server.Listen()
			if err != nil {
				log.Warn().Msgf("Unable to setup listening SOCKS5 on '%s': %s", lc.Internal, err.Error())
				continue
			}

			socks5ProxyServers = append(socks5ProxyServers, server)
			serverWG.Add(1)
			go func(lc *config.ListenConfig) {
				log.Info().Msgf("Listen and serving SOCKS5 on '%s' ==> '%s'", lc.Internal, lc.External)
				err := server.Serve()
				if err != nil {
					log.Error().Msgf("Stopped serving SOCKS5 on '%s' ==> '%s'", lc.Internal, lc.External)
				}
				serverWG.Done()
			}(lc)

		} else if lc.Type == "http" {

			server := httpproxy.NewServer(lc.Internal, lc.External)
			err := server.Listen()
			if err != nil {
				log.Warn().Msgf("Unable to setup listening HTTP on '%s': %s", lc.Internal, err.Error())
				continue
			}

			httpProxyServers = append(httpProxyServers, server)
			serverWG.Add(1)
			go func(lc *config.ListenConfig) {
				log.Info().Msgf("Listen and serving HTTP on '%s' ==> '%s'", lc.Internal, lc.External)
				err := server.Serve()
				if err != nil {
					log.Error().Msgf("Stopped serving HTTP on '%s' ==> '%s'", lc.Internal, lc.External)
				}
				serverWG.Done()
			}(lc)

		}
	}

	if statsServer = stats.CreateStatsServer(); statsServer != nil {
		if statsServer != nil {
			serverWG.Add(1)
			go func() {
				log.Info().Msgf("Listen and serving stats on '%s'", statsServer.Addr)
				err := statsServer.Serve()
				if err != nil {
					log.Error().Msgf("Error running stats web server: %s", err)
				}
				serverWG.Done()
			}()
		}
	}

	if len(socks5ProxyServers) == 0 && len(httpProxyServers) == 0 {
		return fmt.Errorf("not able to listen on any configured IP:port tuple")
	}

	serverWG.Wait()

	return nil
}
