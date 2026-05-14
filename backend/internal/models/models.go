package models

import (
	"time"

	"github.com/google/uuid"
)

type InvestigationStatus string

const (
	StatusPending     InvestigationStatus = "pending"
	StatusAnalyzing   InvestigationStatus = "analyzing"
	StatusReviewing   InvestigationStatus = "reviewing"
	StatusCompleted   InvestigationStatus = "completed"
	StatusEscalated   InvestigationStatus = "escalated"
	StatusFalsePositive InvestigationStatus = "false_positive"
)

type ThreatLevel string

const (
	ThreatNone     ThreatLevel = "none"
	ThreatLow      ThreatLevel = "low"
	ThreatMedium   ThreatLevel = "medium"
	ThreatHigh     ThreatLevel = "high"
	ThreatCritical ThreatLevel = "critical"
)

type Investigation struct {
	ID              uuid.UUID           `json:"id"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
	TenantID        string              `json:"tenant_id"`
	AnalystID       string              `json:"analyst_id,omitempty"`
	Status          InvestigationStatus `json:"status"`
	ThreatLevel     ThreatLevel         `json:"threat_level"`
	ConfidenceScore float64             `json:"confidence_score"`
	
	// Email metadata (NOT raw content)
	Subject         string              `json:"subject"`
	SenderEmail     string              `json:"sender_email"`
	SenderName      string              `json:"sender_name"`
	RecipientCount  int                 `json:"recipient_count"`
	SentAt          time.Time           `json:"sent_at"`
	
	// Authentication results
	SPFResult       string              `json:"spf_result"`
	DKIMResult      string              `json:"dkim_result"`
	DMARCResult     string              `json:"dmarc_result"`
	
	// Analysis results
	Verdict         string              `json:"verdict"`
	AttackChain     []AttackStep        `json:"attack_chain,omitempty"`
	MITREATTCK      []string            `json:"mitre_attack,omitempty"`
	D3FEND          []string            `json:"d3fend,omitempty"`
	
	// Privacy tracking
	SensitivityLevel string             `json:"sensitivity_level"`
	DataMasked      bool                `json:"data_masked"`
	
	IOCs            []IOC               `json:"iocs,omitempty"`
	CampaignID      *uuid.UUID          `json:"campaign_id,omitempty"`
}

type AttackStep struct {
	Order       int     `json:"order"`
	Tactic      string  `json:"tactic"`
	Technique   string  `json:"technique"`
	Description string  `json:"description"`
	Evidence    string  `json:"evidence"`
	Confidence  float64 `json:"confidence"`
}

type IOCType string

const (
	IOCTypeDomain      IOCType = "domain"
	IOCTypeIP          IOCType = "ip"
	IOCTypeURL         IOCType = "url"
	IOCTypeEmail       IOCType = "email"
	IOCTypeHashMD5     IOCType = "hash_md5"
	IOCTypeHashSHA1    IOCType = "hash_sha1"
	IOCTypeHashSHA256  IOCType = "hash_sha256"
	IOCTypeFilename    IOCType = "filename"
	IOCTypeUserAgent   IOCType = "user_agent"
)

type IOC struct {
	ID            uuid.UUID   `json:"id"`
	InvestigationID uuid.UUID `json:"investigation_id"`
	Type          IOCType     `json:"type"`
	Value         string      `json:"value"`
	Normalized    string      `json:"normalized"`
	FirstSeen     time.Time   `json:"first_seen"`
	LastSeen      time.Time   `json:"last_seen"`
	
	// Enrichment data
	ThreatScore   int         `json:"threat_score"`
	ThreatTypes   []string    `json:"threat_types,omitempty"`
	Country       string      `json:"country,omitempty"`
	ASN           string      `json:"asn,omitempty"`
	Registrar     string      `json:"registrar,omitempty"`
	CreatedDate   *time.Time  `json:"created_date,omitempty"`
	ExpiresDate   *time.Time  `json:"expires_date,omitempty"`
	
	// External intelligence
	VirusTotal    *VTResult   `json:"virustotal,omitempty"`
	URLScan       *URLScanResult `json:"urlscan,omitempty"`
	ThreatFox     *ThreatFoxResult `json:"threatfox,omitempty"`
	AbuseIPDB     *AbuseIPDBResult `json:"abuseipdb,omitempty"`
	
	// Correlation
	CampaignIDs   []uuid.UUID `json:"campaign_ids,omitempty"`
	RelatedIOCs   []uuid.UUID `json:"related_iocs,omitempty"`
	
	// Actions
	Blocked       bool        `json:"blocked"`
	BlockedAt     *time.Time  `json:"blocked_at,omitempty"`
	Whitelisted   bool        `json:"whitelisted"`
	WhitelistedAt *time.Time  `json:"whitelisted_at,omitempty"`
}

type VTResult struct {
	Detected     int  `json:"detected"`
	Total        int  `json:"total"`
	Positives    int  `json:"positives"`
	Permalink    string `json:"permalink"`
	LastAnalysis string `json:"last_analysis"`
}

type URLScanResult struct {
	Verdict      string `json:"verdict"`
	Score        int    `json:"score"`
	Categories   []string `json:"categories"`
	Tags         []string `json:"tags"`
	Screenshot   string `json:"screenshot,omitempty"`
}

type ThreatFoxResult struct {
	ThreatType   string `json:"threat_type"`
	MalwareFamily string `json:"malware_family"`
	Confidence   string `json:"confidence"`
}

type AbuseIPDBResult struct {
	AbuseConfidenceScore int    `json:"abuse_confidence_score"`
	TotalReports         int    `json:"total_reports"`
	IsPublic             bool   `json:"is_public"`
	CountryCode          string `json:"country_code"`
	UsageType            string `json:"usage_type"`
}

type Campaign struct {
	ID            uuid.UUID   `json:"id"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
	TenantID      string      `json:"tenant_id"`
	Name          string      `json:"name"`
	Description   string      `json:"description"`
	
	// Campaign characteristics
	TargetBrands  []string    `json:"target_brands,omitempty"`
	TTPs          []string    `json:"ttps,omitempty"`
	Infrastructure []string   `json:"infrastructure,omitempty"`
	
	// Statistics
	InvestigationCount int       `json:"investigation_count"`
	IOCCount           int       `json:"ioc_count"`
	FirstSeen          time.Time `json:"first_seen"`
	LastSeen           time.Time `json:"last_seen"`
	
	// Status
	Active        bool      `json:"active"`
	Confidence    float64   `json:"confidence"`
}

type Attachment struct {
	ID              uuid.UUID   `json:"id"`
	InvestigationID uuid.UUID   `json:"investigation_id"`
	Filename        string      `json:"filename"`
	OriginalFilename string     `json:"original_filename"`
	Size            int64       `json:"size"`
	MimeType        string      `json:"mime_type"`
	MD5             string      `json:"md5"`
	SHA1            string      `json:"sha1"`
	SHA256          string      `json:"sha256"`
	
	// Analysis results
	YARAResults     []YARAMatch `json:"yara_results,omitempty"`
	SandboxVerdict  string      `json:"sandbox_verdict,omitempty"`
	MalwareFamily   string      `json:"malware_family,omitempty"`
	ExtractedText   string      `json:"extracted_text,omitempty"` // OCR result
	
	// Privacy
	LocalPath       string      `json:"-"` // Never serialized
	Encrypted       bool        `json:"encrypted"`
}

type YARAMatch struct {
	RuleName    string            `json:"rule_name"`
	Namespace   string            `json:"namespace"`
	Meta        map[string]string `json:"meta"`
	Strings     []YARAString      `json:"strings"`
}

type YARAString struct {
	Name    string `json:"name"`
	Offset  int    `json:"offset"`
	Data    string `json:"data"`
}

type BrandImpersonation struct {
	ID              uuid.UUID   `json:"id"`
	InvestigationID uuid.UUID   `json:"investigation_id"`
	BrandName       string      `json:"brand_name"`
	DetectedDomain  string      `json:"detected_domain"`
	LegitDomain     string      `json:"legit_domain"`
	SimilarityScore float64     `json:"similarity_score"`
	Method          string      `json:"method"` // homoglyph, typosquat, punycode, etc.
	Evidence        string      `json:"evidence"`
}

type AuditLog struct {
	ID          uuid.UUID `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	TenantID    string    `json:"tenant_id"`
	UserID      string    `json:"user_id"`
	Action      string    `json:"action"`
	Resource    string    `json:"resource"`
	ResourceID  string    `json:"resource_id"`
	Details     string    `json:"details,omitempty"`
	IPAddress   string    `json:"ip_address,omitempty"`
	UserAgent   string    `json:"user_agent,omitempty"`
}

type PrivacyToken struct {
	ID          uuid.UUID `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Original    string    `json:"-"` // Never serialized - encrypted
	Token       string    `json:"token"`
	TokenType   string    `json:"token_type"` // email, domain, ip, url, etc.
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	UsedCount   int       `json:"used_count"`
}
