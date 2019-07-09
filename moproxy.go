// Copyright 2019-2020 Moritz Fain
// Moritz Fain <moritz@fain.io>
package main

import (
	"moproxy/pkg/config"
	"moproxy/pkg/server"

	"github.com/facebookgo/pidfile"
	"github.com/jessevdk/go-flags"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"fmt"
	"io"
	"os"
	"time"
)

const version string = "0.3.0"

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
		fmt.Println(version)
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
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	log.Logger = log.Output(consoleWriter).With().Caller().Logger()

	f, err := os.OpenFile(mainOpts.LogFile, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		log.Warn().Msgf("Error opening log file: %s; logging only on console!", mainOpts.LogFile)
	} else {
		log.Logger = log.Output(io.MultiWriter(consoleWriter, f))
	}
	defer f.Close()

	if len(mainOpts.Verbose) == 0 {
		log.Logger = log.Logger.Level(zerolog.WarnLevel)
	} else if len(mainOpts.Verbose) == 1 {
		log.Logger = log.Logger.Level(zerolog.InfoLevel)
	} else if len(mainOpts.Verbose) >= 2 {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
	}

	// Load config
	_, err = config.LoadConfig(mainOpts.Config)
	if err != nil {
		log.Error().Msgf("Error reading config: %s", err)
		os.Exit(2)
	}

	// Write pid file (if given)
	if mainOpts.Pidfile != "" {
		log.Debug().Msgf("Writing pid file: %s", mainOpts.Pidfile)
		pidfile.SetPidfilePath(mainOpts.Pidfile)
		pidfile.Write()
	}

	// Serve
	err = server.Run()
	if err != nil {
		log.Error().Msgf("Error running server: %s", err)
		os.Exit(3)
	}

	log.Info().Msg("Goodbye!")
}
