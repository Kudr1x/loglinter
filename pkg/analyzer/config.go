package analyzer

import (
	"encoding/json"
	"os"
)

type Config struct {
	SensitiveWords []string `json:"sensitive_words"`
	Patterns       []string `json:"patterns"` // <-- Новое поле в конфиге
}

var defaultConfig = Config{
	SensitiveWords: []string{"password", "token", "secret", "api_key", "apikey", "credential"},
	Patterns:       []string{},
}

func loadConfig() Config {
	file, err := os.Open(".loglinter.json")
	if err != nil {
		return defaultConfig
	}
	defer file.Close()

	var cfg Config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return defaultConfig
	}
	return cfg
}
