package logger

import (
	"log/slog"
	"os"
)

var Logger *slog.Logger

func InitializeLogger(logLevel slog.Level) {
	// Create a new logger with the specified log level
	Logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
}
