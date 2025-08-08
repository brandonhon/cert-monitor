package logger

import (
	"io"
	"os"

	log "github.com/sirupsen/logrus"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

// Config holds logger configuration
type Config struct {
	File     string
	Level    string
	DryRun   bool
}

// Init initializes the logger with default settings
func Init() {
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})
	log.SetLevel(log.InfoLevel)
}

// InitWithConfig initializes the logger with specific configuration
func InitWithConfig(cfg Config) error {
	// Set log level
	level, err := log.ParseLevel(cfg.Level)
	if err != nil {
		level = log.InfoLevel
	}
	log.SetLevel(level)

	// Configure output
	if cfg.File != "" {
		logWriter := &lumberjack.Logger{
			Filename:   cfg.File,
			MaxSize:    25, // megabytes
			MaxBackups: 3,
			MaxAge:     28, // days
			Compress:   true,
		}

		if cfg.DryRun {
			log.SetOutput(io.MultiWriter(os.Stdout, logWriter))
		} else {
			log.SetOutput(logWriter)
		}
	}

	// Configure formatter
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		DisableColors: !cfg.DryRun,
	})

	return nil
}