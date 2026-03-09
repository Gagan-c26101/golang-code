package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds application configuration
type Config struct {
	Port            string
	DBName          string
	JWTKey          string
	SaltRound       int
	LocalTextApi    string
	LocalTextApiUrl string

	AOCSmsApiKey string
	AOCSmsApiURL string
	AOCSmsSender string

	SmsSender          string
	SendgridApiKey     string
	SendgridSenderMail string
	SendgridSenderName string
	SandboxApiURL      string
	SandboxApiKey      string
	SandboxSecretKey   string
	SandboxApiVersion  string
	EncryptionKey      string
	AppName            string
	OTPExpiryMinutes   int
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
		Port:            getEnv("PORT", "defaultSecret"),
		DBName:          getEnv("DB_NAME", "defaultSecret"),
		JWTKey:          getEnv("JWT_SECRET_KEY", "defaultSecret"),
		SaltRound:       getEnvInt("SALT_ROUND", 10),
		LocalTextApi:    getEnv("LOCAL_SMS_API_KEY", "defaultSecret"),
		LocalTextApiUrl: getEnv("LOCAL_SMS_API_URL", "defaultSecret"),

		AOCSmsApiKey: getEnv("AOC_SMS_API_KEY", ""),
		AOCSmsApiURL: getEnv("AOC_SMS_API_URL", "defaultSecret"),
		AOCSmsSender: getEnv("AOC_SMS_SENDER", "defaultSecret"),

		SmsSender:          getEnv("SMS_SENDER", "defaultSecret"),
		SendgridApiKey:     getEnv("SENDGRID_API_KEY", "defaultSecret"),
		SendgridSenderMail: getEnv("SENDGRID_MAIL_FROM", "defaultSecret"),
		SendgridSenderName: getEnv("SENDGRID_MAIL_NAME", "defaultSecret"),
		SandboxApiURL:      getEnv("SANDBOX_API_URL", "defaultSecret"),
		SandboxApiKey:      getEnv("SANDBOX_API_KEY", "defaultSecret"),
		SandboxSecretKey:   getEnv("SANDBOX_SECRET_KEY", "defaultSecret"),
		SandboxApiVersion:  getEnv("SANDBOX_API_VERSION", "defaultSecret"),
		EncryptionKey:      getEnv("ENCRYPTION_KEY", ""),
		AppName:            getEnv("APP_NAME", "defaultSecret"),
		OTPExpiryMinutes:   getEnvInt("OTP_EXPIRY_MINUTES", 2),
	}

	// Validate critical configuration
	if AppConfig.JWTKey == "defaultSecret" {
		log.Println("Warning: Using default JWT_SECRET_KEY. Update it in your environment.")
	}
	if AppConfig.DBName == "User.db" {
		log.Println("Warning: Using default DBName. Update it in your environment.")
	}

}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

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
