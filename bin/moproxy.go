// Copyright 2019-2021 Moritz Fain
// Moritz Fain <moritz@fain.io>

package main

import (
	"moproxy/pkg/config"
	"moproxy/pkg/misc"
	"moproxy/pkg/server"

	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/facebookgo/pidfile"
	"github.com/jessevdk/go-flags"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var VERSION = "dev"
var BUILDDIR = ""

var mainOpts struct {
	Config  string `short:"c" long:"config" description:"Config file" value-name:"FILE" default:"./configs/moproxy.conf"`
	LogFile string `short:"l" long:"logfile" description:"Log file" value-name:"FILE" default:"./logs/moproxy.log"`
	Pidfile string `short:"p" long:"pidfile" description:"Pid file" value-name:"FILE"`
	Verbose []bool `short:"v" long:"verbose" description:"Show verbose debug information"`
	Version bool   `long:"version" description:"Show moproxy version"`
}

func main() {
	// Parse flags and arguments
	parser := flags.NewParser(&mainOpts, flags.HelpFlag)
	_, err := parser.Parse()

	if mainOpts.Version {
		fmt.Println(VERSION)
		os.Exit(0)
	}

	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			// normal help behaviour
		} else {
			fmt.Println("Usage error:", err)
			fmt.Println()
		}
		parser.WriteHelp(os.Stdout)
		os.Exit(1)
	}

	// Set up logging
	reloadChan := make(chan os.Signal)
	signal.Notify(reloadChan, syscall.SIGHUP)

	buildDirPrefix := BUILDDIR
	if buildDirPrefix == "" {
		buildDirPrefix, _ = os.Getwd()
	}

	zerolog.CallerMarshalFunc = func(file string, line int) string {
		file = strings.TrimPrefix(strings.TrimPrefix(file, buildDirPrefix), "/")
		return file + ":" + strconv.Itoa(line)
	}

	log.Logger = log.Logger.With().Caller().Logger()
	if len(mainOpts.Verbose) == 0 {
		log.Logger = log.Logger.Level(zerolog.WarnLevel)
	} else if len(mainOpts.Verbose) == 1 {
		log.Logger = log.Logger.Level(zerolog.InfoLevel)
	} else if len(mainOpts.Verbose) >= 2 {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	}

	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	log.Logger = log.Output(consoleWriter).With().Caller().Logger()

	rw, err := misc.NewRotateWriter(mainOpts.LogFile, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		log.Warn().Msgf("Error opening log file: %s; logging only on console!", mainOpts.LogFile)
	} else {
		defer rw.Close()
		log.Logger = log.Output(io.MultiWriter(consoleWriter, rw))
	}

	go func() {
		//  rotate writer in case of SIGHUP (for log rotate)
		for {
			<-reloadChan
			rw.Rotate()
		}
	}()

	// Write pid file (if given)
	if mainOpts.Pidfile != "" {
		log.Debug().Msgf("Writing pid file: %s", mainOpts.Pidfile)
		pidfile.SetPidfilePath(mainOpts.Pidfile)
		err = pidfile.Write()
		if err != nil {
			log.Error().Msgf("Error writing pid file: %s", err)
			os.Exit(4)
		}
	}

	// Serve
	err = server.Run(func() *config.Configuration {
		// Load config
		configInstance, err := config.LoadConfig(mainOpts.Config)
		if err != nil {
			log.Error().Msgf("Error reading config: %s", err)
			os.Exit(2)
		}
		return configInstance
	})

	if err != nil {
		log.Error().Msgf("Error running server: %s", err)
		os.Exit(3)
	}

	log.Info().Msg("Goodbye!")
}
