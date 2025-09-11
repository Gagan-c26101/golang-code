package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds application configuration
type Config struct {
	Port               string
	DBName             string
	JWTKey             string
	SaltRound          int
	LocalTextApi       string
	LocalTextApiUrl    string
	SendgridApiKey     string
	SendgridSenderMail string
	SandgridSenderName string
	SandboxApiURL      string // Added for Sandbox API URL
	SandboxApiKey      string // Added for Sandbox API Key
	SandboxSecretKey   string // Added for Sandbox Secret Key
	SandboxApiVersion  string // Added for Sandbox API Version
}

// AppConfig is a global variable to access configuration
var AppConfig *Config

// LoadConfig initializes configuration from environment variables or defaults
func LoadConfig() {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("Warning: .env file not found. Using system environment variables.")
	}

	// Initialize AppConfig with values from environment variables
	AppConfig = &Config{
		Port:               getEnv("PORT", "3000"),
		DBName:             getEnv("DB_NAME", "credUser.db"),
		JWTKey:             getEnv("JWT_SECRET_KEY", "defaultSecret"),
		SaltRound:          getEnvInt("SALT_ROUND", 10),
		LocalTextApi:       getEnv("LOCAL_SMS_API_KEY", "defaultSecret"),
		LocalTextApiUrl:    getEnv("LOCAL_SMS_API_URL", "defaultSecret"),
		SendgridApiKey:     getEnv("SENDGRID_API_KEY", "defaultSecret"),
		SendgridSenderMail: getEnv("SENDGRID_MAIL_FROM", "defaultSecret"),
		SandgridSenderName: getEnv("SENDGRID_MAIL_NAME", "defaultSecret"),
		SandboxApiURL:      getEnv("SANDBOX_API_URL", "actual key"),
		SandboxApiKey:      getEnv("SANDBOX_API_KEY", "actual key"),
		SandboxSecretKey:   getEnv("SANDBOX_SECRET_KEY", "actual key"),
		SandboxApiVersion:  getEnv("SANDBOX_API_VERSION", "2.0"),
	}

	// Validate critical configuration
	if AppConfig.JWTKey == "defaultSecret" {
		log.Println("Warning: Using default JWT_SECRET_KEY. Update it in your environment.")
	}
	if AppConfig.DBName == "credUser.db" {
		log.Println("Warning: Using default DBName. Update it in your environment.")
	}
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// getEnvInt retrieves an environment variable as an integer or returns the default integer value
func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	intValue, err := strconv.Atoi(value)
	if err != nil {
		log.Printf("Error converting environment variable %s to int: %v", key, err)
		return defaultValue
	}
	return intValue
}
