package test

import (
	"log/slog"

	"go.uber.org/zap"
)

var logger *zap.Logger

func validLogs() {
	slog.Info("starting server on port 8080")
	slog.Error("failed to connect to database")
	logger.Info("server started")
	logger.Error("connection failed")
	logger.Warn("something went wrong")
	slog.Info("user authenticated successfully")
	logger.Debug("api request completed")
	slog.Info("token validated")
}

func invalidLogs() {
	password := "my_secret_pass"
	apiKey := "12345"
	token := "abcde"

	slog.Info("Starting server on port 8080")   // want "log message must start with a lowercase letter"
	slog.Error("Failed to connect to database") // want "log message must start with a lowercase letter"

	slog.Info("запуск сервера")                      // want "log message must be in English only"
	logger.Error("ошибка подключения к базе данных") // want "log message must be in English only"

	slog.Info("server started!")                    // want "log message must not contain special characters or emojis.*"
	logger.Error("connection failed!!!")            // want "log message must not contain special characters or emojis.*"
	logger.Warn("warning: something went wrong...") // want "log message must not contain special characters or emojis.*"

	slog.Info("user password " + password) // want "log message contains potentially sensitive data.*"
	logger.Debug("apikey " + apiKey)       // want "log message contains potentially sensitive data.*"
	slog.Info("token " + token)            // want "log message contains potentially sensitive data.*"
}
