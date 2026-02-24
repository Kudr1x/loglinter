package test

type slogLogger struct{}

func (l *slogLogger) Info(msg ...any)  {}
func (l *slogLogger) Error(msg ...any) {}

type zapLogger struct{}

func (l *zapLogger) Debug(msg ...any) {}
func (l *zapLogger) Warn(msg ...any)  {}
func (l *zapLogger) Info(msg ...any)  {}
func (l *zapLogger) Error(msg ...any) {}

var slog = &slogLogger{}
var log = &zapLogger{}

func validLogs() {
	slog.Info("starting server on port 8080")
	slog.Error("failed to connect to database")
	log.Info("server started")
	log.Error("connection failed")
	log.Warn("something went wrong")
	slog.Info("user authenticated successfully")
	log.Debug("api request completed")
	slog.Info("token validated")
}

func invalidLogs() {
	password := "my_secret_pass"
	apiKey := "12345"
	token := "abcde"

	slog.Info("Starting server on port 8080")   // want "log message must start with a lowercase letter"
	slog.Error("Failed to connect to database") // want "log message must start with a lowercase letter"

	slog.Info("запуск сервера")                   // want "log message must be in English only"
	log.Error("ошибка подключения к базе данных") // want "log message must be in English only"

	slog.Info("server started!")                 // want "log message must not contain special characters or emojis.*"
	log.Error("connection failed!!!")            // want "log message must not contain special characters or emojis.*"
	log.Warn("warning: something went wrong...") // want "log message must not contain special characters or emojis.*"

	slog.Info("user password " + password) // want "log message contains potentially sensitive data.*"
	log.Debug("apikey " + apiKey)          // want "log message contains potentially sensitive data.*"
	slog.Info("token " + token)            // want "log message contains potentially sensitive data.*"
}
