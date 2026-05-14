package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"phishguard/internal/config"
)

type Database struct {
	db *sql.DB
}

func NewDatabase(cfg config.DatabaseConfig) (*Database, error) {
	db, err := sql.Open("sqlite3", cfg.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnLifetime)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	d := &Database{db: db}

	// Run migrations
	if err := d.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return d, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) DB() *sql.DB {
	return d.db
}

func (d *Database) migrate() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS investigations (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			analyst_id TEXT,
			status TEXT NOT NULL DEFAULT 'pending',
			threat_level TEXT NOT NULL DEFAULT 'none',
			confidence_score REAL DEFAULT 0.0,
			subject TEXT,
			sender_email TEXT,
			sender_name TEXT,
			recipient_count INTEGER DEFAULT 0,
			sent_at DATETIME,
			spf_result TEXT,
			dkim_result TEXT,
			dmarc_result TEXT,
			verdict TEXT,
			attack_chain TEXT,
			mitre_attack TEXT,
			d3fend TEXT,
			sensitivity_level TEXT DEFAULT 'internal',
			data_masked BOOLEAN DEFAULT FALSE,
			campaign_id TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_investigations_tenant ON investigations(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_investigations_status ON investigations(status)`,
		`CREATE INDEX IF NOT EXISTS idx_investigations_threat ON investigations(threat_level)`,
		`CREATE INDEX IF NOT EXISTS idx_investigations_created ON investigations(created_at)`,

		`CREATE TABLE IF NOT EXISTS iocs (
			id TEXT PRIMARY KEY,
			investigation_id TEXT NOT NULL,
			type TEXT NOT NULL,
			value TEXT NOT NULL,
			normalized TEXT,
			threat_score INTEGER DEFAULT 0,
			threat_types TEXT,
			country TEXT,
			asn TEXT,
			registrar TEXT,
			created_date DATETIME,
			expires_date DATETIME,
			virustotal TEXT,
			urlscan TEXT,
			threatfox TEXT,
			abuseipdb TEXT,
			campaign_ids TEXT,
			related_iocs TEXT,
			blocked BOOLEAN DEFAULT FALSE,
			blocked_at DATETIME,
			whitelisted BOOLEAN DEFAULT FALSE,
			whitelisted_at DATETIME,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_iocs_investigation ON iocs(investigation_id)`,
		`CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)`,
		`CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value)`,
		`CREATE INDEX IF NOT EXISTS idx_iocs_threat ON iocs(threat_score)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_unique ON iocs(type, normalized)`,

		`CREATE TABLE IF NOT EXISTS campaigns (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			name TEXT NOT NULL,
			description TEXT,
			target_brands TEXT,
			ttps TEXT,
			infrastructure TEXT,
			investigation_count INTEGER DEFAULT 0,
			ioc_count INTEGER DEFAULT 0,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			active BOOLEAN DEFAULT TRUE,
			confidence REAL DEFAULT 0.0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_campaigns_tenant ON campaigns(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_campaigns_active ON campaigns(active)`,

		`CREATE TABLE IF NOT EXISTS attachments (
			id TEXT PRIMARY KEY,
			investigation_id TEXT NOT NULL,
			filename TEXT NOT NULL,
			original_filename TEXT,
			size INTEGER NOT NULL,
			mime_type TEXT,
			md5 TEXT,
			sha1 TEXT,
			sha256 TEXT NOT NULL,
			yara_results TEXT,
			sandbox_verdict TEXT,
			malware_family TEXT,
			extracted_text TEXT,
			local_path TEXT,
			encrypted BOOLEAN DEFAULT TRUE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_attachments_investigation ON attachments(investigation_id)`,
		`CREATE INDEX IF NOT EXISTS idx_attachments_sha256 ON attachments(sha256)`,

		`CREATE TABLE IF NOT EXISTS brand_impersonations (
			id TEXT PRIMARY KEY,
			investigation_id TEXT NOT NULL,
			brand_name TEXT NOT NULL,
			detected_domain TEXT NOT NULL,
			legit_domain TEXT,
			similarity_score REAL NOT NULL,
			method TEXT,
			evidence TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY (investigation_id) REFERENCES investigations(id) ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS idx_brand_investigation ON brand_impersonations(investigation_id)`,

		`CREATE TABLE IF NOT EXISTS privacy_tokens (
			id TEXT PRIMARY KEY,
			tenant_id TEXT NOT NULL,
			token TEXT NOT NULL UNIQUE,
			token_type TEXT NOT NULL,
			original_encrypted TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			expires_at DATETIME NOT NULL,
			used_count INTEGER DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_tenant ON privacy_tokens(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_token ON privacy_tokens(token)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_expires ON privacy_tokens(expires_at)`,

		`CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
			tenant_id TEXT NOT NULL,
			user_id TEXT,
			action TEXT NOT NULL,
			resource TEXT NOT NULL,
			resource_id TEXT,
			details TEXT,
			ip_address TEXT,
			user_agent TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs(tenant_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action)`,
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, migration := range migrations {
		if _, err := tx.Exec(migration); err != nil {
			return fmt.Errorf("migration error: %w", err)
		}
	}

	return tx.Commit()
}

// HealthCheck returns database health status
func (d *Database) HealthCheck() (bool, error) {
	err := d.db.Ping()
	return err == nil, err
}

// Stats returns database statistics
func (d *Database) Stats() map[string]interface{} {
	stats := d.db.Stats()
	return map[string]interface{}{
		"max_open_connections":     stats.MaxOpenConnections,
		"open_connections":         stats.OpenConnections,
		"in_use":                   stats.InUse,
		"idle":                     stats.Idle,
		"wait_count":               stats.WaitCount,
		"wait_duration_ms":         stats.WaitDuration.Milliseconds(),
		"max_idle_closed":          stats.MaxIdleClosed,
		"max_lifetime_closed":      stats.MaxLifetimeClosed,
	}
}

// LogAudit creates an audit log entry
func (d *Database) LogAudit(tenantID, userID, action, resource, resourceID, details, ip, ua string) error {
	query := `INSERT INTO audit_logs (id, tenant_id, user_id, action, resource, resource_id, details, ip_address, user_agent) 
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	_, err := d.db.Exec(query, id, tenantID, userID, action, resource, resourceID, details, ip, ua)
	return err
}
