package config

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server      ServerConfig
	Database    DatabaseConfig
	Redis       RedisConfig
	NATS        NATSConfig
	AI          AIConfig
	Security    SecurityConfig
	Sandbox     SandboxConfig
	Privacy     PrivacyConfig
}

type ServerConfig struct {
	Host         string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type DatabaseConfig struct {
	Path        string
	MaxOpenConns int
	MaxIdleConns int
	ConnLifetime time.Duration
}

type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
	PoolSize int
}

type NATSConfig struct {
	URL           string
	QueueGroup    string
	MaxReconnects int
	ReconnectWait time.Duration
}

type AIConfig struct {
	LiteLLMEndpoint   string
	DeepSeekAPIKey    string
	ClaudeAPIKey      string
	OllamaEndpoint    string
	DefaultModel      string
	MaxTokens         int
	Temperature       float64
	RequestTimeout    time.Duration
	MaxRetries        int
}

type SecurityConfig struct {
	EncryptionKey    []byte
	JWTSecret        string
	SessionTimeout   time.Duration
	MaxUploadSize    int64
	AllowedMimeTypes []string
}

type SandboxConfig struct {
	DockerSocket     string
	NetworkDisabled  bool
	MemoryLimit      int64
	CPULimit         float64
	Timeout          time.Duration
	MaxConcurrent    int
}

type PrivacyConfig struct {
	EnableMasking      bool
	MinConfidenceScore float64
	RequireApproval    bool
	AuditLogging       bool
}

func Load() (*Config, error) {
	encKey := os.Getenv("ENCRYPTION_KEY")
	if encKey == "" {
		// Generate random key for development
		encKey = base64.StdEncoding.EncodeToString([]byte("default-key-change-in-production"))
	}

	port, _ := strconv.Atoi(getEnv("SERVER_PORT", "8080"))
	redisPort, _ := strconv.Atoi(getEnv("REDIS_PORT", "6379"))
	redisDB, _ := strconv.Atoi(getEnv("REDIS_DB", "0"))
	redisPool, _ := strconv.Atoi(getEnv("REDIS_POOL_SIZE", "10"))
	natsMaxReconnect, _ := strconv.Atoi(getEnv("NATS_MAX_RECONNECTS", "5"))
	maxTokens, _ := strconv.Atoi(getEnv("AI_MAX_TOKENS", "2048"))
	maxRetries, _ := strconv.Atoi(getEnv("AI_MAX_RETRIES", "3"))
	temp, _ := strconv.ParseFloat(getEnv("AI_TEMPERATURE", "0.3"), 64)
	maxUpload, _ := strconv.ParseInt(getEnv("MAX_UPLOAD_SIZE", "10485760"), 10, 64) // 10MB default
	memoryLimit, _ := strconv.ParseInt(getEnv("SANDBOX_MEMORY_LIMIT", "268435456"), 10, 64) // 256MB
	cpuLimit, _ := strconv.ParseFloat(getEnv("SANDBOX_CPU_LIMIT", "1.0"), 64)
	minConfidence, _ := strconv.ParseFloat(getEnv("PRIVACY_MIN_CONFIDENCE", "0.8"), 64)

	timeout := func(env string, defaultSec int) time.Duration {
		if v := os.Getenv(env); v != "" {
			if sec, err := strconv.Atoi(v); err == nil {
				return time.Duration(sec) * time.Second
			}
		}
		return time.Duration(defaultSec) * time.Second
	}

	natsReconnectWait := timeout("NATS_RECONNECT_WAIT", 2)

	return &Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Port:         port,
			ReadTimeout:  timeout("SERVER_READ_TIMEOUT", 30),
			WriteTimeout: timeout("SERVER_WRITE_TIMEOUT", 30),
			IdleTimeout:  timeout("SERVER_IDLE_TIMEOUT", 120),
		},
		Database: DatabaseConfig{
			Path:         getEnv("DATABASE_PATH", "./data/phishguard.db"),
			MaxOpenConns: 25,
			MaxIdleConns: 5,
			ConnLifetime: 5 * time.Minute,
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     redisPort,
			Password: os.Getenv("REDIS_PASSWORD"),
			DB:       redisDB,
			PoolSize: redisPool,
		},
		NATS: NATSConfig{
			URL:           getEnv("NATS_URL", "nats://localhost:4222"),
			QueueGroup:    getEnv("NATS_QUEUE_GROUP", "phishguard-workers"),
			MaxReconnects: natsMaxReconnect,
			ReconnectWait: natsReconnectWait,
		},
		AI: AIConfig{
			LiteLLMEndpoint: getEnv("LITELLM_ENDPOINT", "http://localhost:4000"),
			DeepSeekAPIKey:  os.Getenv("DEEPSEEK_API_KEY"),
			ClaudeAPIKey:    os.Getenv("CLAUDE_API_KEY"),
			OllamaEndpoint:  getEnv("OLLAMA_ENDPOINT", "http://localhost:11434"),
			DefaultModel:    getEnv("AI_DEFAULT_MODEL", "claude-3-haiku"),
			MaxTokens:       maxTokens,
			Temperature:     temp,
			RequestTimeout:  timeout("AI_REQUEST_TIMEOUT", 60),
			MaxRetries:      maxRetries,
		},
		Security: SecurityConfig{
			EncryptionKey:  []byte(encKey),
			JWTSecret:      getEnv("JWT_SECRET", "change-me-in-production"),
			SessionTimeout: timeout("SESSION_TIMEOUT", 3600),
			MaxUploadSize:  maxUpload,
			AllowedMimeTypes: []string{
				"message/rfc822",
				"application/octet-stream",
			},
		},
		Sandbox: SandboxConfig{
			DockerSocket:    getEnv("DOCKER_SOCKET", "/var/run/docker.sock"),
			NetworkDisabled: true,
			MemoryLimit:     memoryLimit,
			CPULimit:        cpuLimit,
			Timeout:         timeout("SANDBOX_TIMEOUT", 300),
			MaxConcurrent:   5,
		},
		Privacy: PrivacyConfig{
			EnableMasking:      getEnv("PRIVACY_ENABLE_MASKING", "true") == "true",
			MinConfidenceScore: minConfidence,
			RequireApproval:    getEnv("PRIVACY_REQUIRE_APPROVAL", "true") == "true",
			AuditLogging:       getEnv("PRIVACY_AUDIT_LOGGING", "true") == "true",
		},
	}, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func (c *Config) ServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

func (c *Config) RedisAddr() string {
	return fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port)
}
