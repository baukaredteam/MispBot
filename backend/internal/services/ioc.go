package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"phishguard/internal/database"
	"phishguard/internal/models"
	"phishguard/internal/privacy"
)

type IOCService struct {
	db          *database.Database
	privGateway *privacy.PrivacyGateway
	httpClient  *http.Client
}

func NewIOCService(db *database.Database, priv *privacy.PrivacyGateway) *IOCService {
	return &IOCService{
		db: db,
		privGateway: priv,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// EnrichIOC enriches an IOC with external threat intelligence
func (s *IOCService) EnrichIOC(ctx context.Context, iocID uuid.UUID) (*models.IOC, error) {
	ioc, err := s.GetIOC(iocID)
	if err != nil {
		return nil, err
	}

	switch ioc.Type {
	case models.IOCTypeDomain:
		if err := s.enrichDomain(ctx, ioc); err != nil {
			return nil, err
		}
	case models.IOCTypeIP:
		if err := s.enrichIP(ctx, ioc); err != nil {
			return nil, err
		}
	case models.IOCTypeURL:
		if err := s.enrichURL(ctx, ioc); err != nil {
			return nil, err
		}
	case models.IOCTypeHashMD5, models.IOCTypeHashSHA1, models.IOCTypeHashSHA256:
		if err := s.enrichHash(ctx, ioc); err != nil {
			return nil, err
		}
	}

	if err := s.saveIOC(ioc); err != nil {
		return nil, err
	}

	return ioc, nil
}

func (s *IOCService) enrichDomain(ctx context.Context, ioc *models.IOC) error {
	// WHOIS lookup (simplified - would use actual WHOIS API)
	// Passive DNS (would use SecurityTrails, RiskIQ, etc.)
	
	// Check for suspicious TLDs
	suspiciousTLDs := []string{".xyz", ".top", ".club", ".work", ".click", ".link", ".gq", ".ml", ".cf", ".tk", ".ga"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(strings.ToLower(ioc.Value), tld) {
			ioc.ThreatScore += 10
		}
	}

	// Check domain age (new domains are more suspicious)
	// This would be populated from WHOIS data
	
	return nil
}

func (s *IOCService) enrichIP(ctx context.Context, ioc *models.IOC) error {
	// AbuseIPDB lookup
	valid, isPrivate, isInternal := privacy.ValidateIPAddress(ioc.Value)
	if !valid {
		return fmt.Errorf("invalid IP address")
	}

	if isPrivate || isInternal {
		// Internal IPs have lower threat score typically
		ioc.ThreatScore = max(0, ioc.ThreatScore-10)
		return nil
	}

	// Call AbuseIPDB API (would implement actual API call)
	// For now, just mark that enrichment was attempted
	
	return nil
}

func (s *IOCService) enrichURL(ctx context.Context, ioc *models.IOC) error {
	// URLScan.io lookup (would implement actual API call)
	// Check for URL shorteners
	shorteners := []string{"bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd"}
	for _, s := range shorteners {
		if strings.Contains(strings.ToLower(ioc.Value), s) {
			ioc.ThreatScore += 15
			break
		}
	}

	return nil
}

func (s *IOCService) enrichHash(ctx context.Context, ioc *models.IOC) error {
	// VirusTotal lookup (would implement actual API call)
	// MalwareBazaar lookup
	
	return nil
}

// GetIOC retrieves an IOC by ID
func (s *IOCService) GetIOC(id uuid.UUID) (*models.IOC, error) {
	query := `SELECT id, investigation_id, type, value, normalized, threat_score,
		threat_types, country, asn, registrar, created_date, expires_date,
		virustotal, urlscan, threatfox, abuseipdb, campaign_ids, related_iocs,
		blocked, blocked_at, whitelisted, whitelisted_at, first_seen, last_seen
		FROM iocs WHERE id = ?`

	row := s.db.DB().QueryRow(query, id.String())

	ioc := &models.IOC{}
	var idStr, invStr, typesStr, vtStr, usStr, tfStr, abStr, campStr, relStr sql.NullString
	var createdDate, expiresDate, blockedAt, whitelistedAt sql.NullTime

	err := row.Scan(
		&idStr, &invStr, &ioc.Type, &ioc.Value, &ioc.Normalized,
		&ioc.ThreatScore, &typesStr, &ioc.Country, &ioc.ASN, &ioc.Registrar,
		&createdDate, &expiresDate, &vtStr, &usStr, &tfStr, &abStr,
		&campStr, &relStr, &ioc.Blocked, &blockedAt, &ioc.Whitelisted, &whitelistedAt,
		&ioc.FirstSeen, &ioc.LastSeen,
	)

	if err != nil {
		return nil, err
	}

	ioc.ID, _ = uuid.Parse(idStr.String)
	ioc.InvestigationID, _ = uuid.Parse(invStr.String)

	if typesStr.Valid {
		json.Unmarshal([]byte(typesStr.String), &ioc.ThreatTypes)
	}

	if vtStr.Valid {
		json.Unmarshal([]byte(vtStr.String), &ioc.VirusTotal)
	}

	if usStr.Valid {
		json.Unmarshal([]byte(usStr.String), &ioc.URLScan)
	}

	if tfStr.Valid {
		json.Unmarshal([]byte(tfStr.String), &ioc.ThreatFox)
	}

	if abStr.Valid {
		json.Unmarshal([]byte(abStr.String), &ioc.AbuseIPDB)
	}

	if createdDate.Valid {
		ioc.CreatedDate = &createdDate.Time
	}

	if expiresDate.Valid {
		ioc.ExpiresDate = &expiresDate.Time
	}

	if blockedAt.Valid {
		ioc.BlockedAt = &blockedAt.Time
	}

	if whitelistedAt.Valid {
		ioc.WhitelistedAt = &whitelistedAt.Time
	}

	return ioc, nil
}

func (s *IOCService) saveIOC(ioc *models.IOC) error {
	query := `UPDATE iocs SET threat_score = ?, threat_types = ?, country = ?,
		asn = ?, registrar = ?, created_date = ?, expires_date = ?,
		virustotal = ?, urlscan = ?, threatfox = ?, abuseipdb = ?,
		campaign_ids = ?, related_iocs = ?, blocked = ?, blocked_at = ?,
		whitelisted = ?, whitelisted_at = ?, last_seen = ?
		WHERE id = ?`

	var typesJSON, vtJSON, usJSON, tfJSON, abJSON, campJSON, relJSON sql.NullString

	if len(ioc.ThreatTypes) > 0 {
		data, _ := json.Marshal(ioc.ThreatTypes)
		typesJSON = sql.NullString{String: string(data), Valid: true}
	}

	if ioc.VirusTotal != nil {
		data, _ := json.Marshal(ioc.VirusTotal)
		vtJSON = sql.NullString{String: string(data), Valid: true}
	}

	if ioc.URLScan != nil {
		data, _ := json.Marshal(ioc.URLScan)
		usJSON = sql.NullString{String: string(data), Valid: true}
	}

	if ioc.ThreatFox != nil {
		data, _ := json.Marshal(ioc.ThreatFox)
		tfJSON = sql.NullString{String: string(data), Valid: true}
	}

	if ioc.AbuseIPDB != nil {
		data, _ := json.Marshal(ioc.AbuseIPDB)
		abJSON = sql.NullString{String: string(data), Valid: true}
	}

	if len(ioc.CampaignIDs) > 0 {
		data, _ := json.Marshal(ioc.CampaignIDs)
		campJSON = sql.NullString{String: string(data), Valid: true}
	}

	if len(ioc.RelatedIOCs) > 0 {
		data, _ := json.Marshal(ioc.RelatedIOCs)
		relJSON = sql.NullString{String: string(data), Valid: true}
	}

	_, err := s.db.DB().Exec(query,
		ioc.ThreatScore, typesJSON, ioc.Country, ioc.ASN, ioc.Registrar,
		ioc.CreatedDate, ioc.ExpiresDate,
		vtJSON, usJSON, tfJSON, abJSON, campJSON, relJSON,
		ioc.Blocked, ioc.BlockedAt, ioc.Whitelisted, ioc.WhitelistedAt,
		time.Now().UTC(), ioc.ID.String(),
	)

	return err
}

// BlockIOC marks an IOC as blocked
func (s *IOCService) BlockIOC(id uuid.UUID, reason string) error {
	now := time.Now().UTC()
	query := `UPDATE iocs SET blocked = TRUE, blocked_at = ? WHERE id = ?`
	_, err := s.db.DB().Exec(query, now, id.String())
	return err
}

// WhitelistIOC marks an IOC as whitelisted
func (s *IOCService) WhitelistIOC(id uuid.UUID, reason string) error {
	now := time.Now().UTC()
	query := `UPDATE iocs SET whitelisted = TRUE, whitelisted_at = ? WHERE id = ?`
	_, err := s.db.DB().Exec(query, now, id.String())
	return err
}

// SearchIOCs searches for IOCs matching criteria
func (s *IOCService) SearchIOCs(query string, iocType string, minThreatScore int) ([]models.IOC, error) {
	sqlQuery := `SELECT id, investigation_id, type, value, normalized, threat_score,
		threat_types, country, asn, blocked, whitelisted, first_seen, last_seen
		FROM iocs WHERE 1=1`

	args := []interface{}{}

	if query != "" {
		sqlQuery += " AND (value LIKE ? OR normalized LIKE ?)"
		args = append(args, "%"+query+"%", "%"+query+"%")
	}

	if iocType != "" {
		sqlQuery += " AND type = ?"
		args = append(args, iocType)
	}

	if minThreatScore > 0 {
		sqlQuery += " AND threat_score >= ?"
		args = append(args, minThreatScore)
	}

	sqlQuery += " ORDER BY threat_score DESC, last_seen DESC LIMIT 100"

	rows, err := s.db.DB().Query(sqlQuery, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var iocs []models.IOC
	for rows.Next() {
		var ioc models.IOC
		var idStr, invStr, typesStr sql.NullString

		err := rows.Scan(
			&idStr, &invStr, &ioc.Type, &ioc.Value, &ioc.Normalized,
			&ioc.ThreatScore, &typesStr, &ioc.Country, &ioc.ASN,
			&ioc.Blocked, &ioc.Whitelisted, &ioc.FirstSeen, &ioc.LastSeen,
		)
		if err != nil {
			return nil, err
		}

		ioc.ID, _ = uuid.Parse(idStr.String)
		ioc.InvestigationID, _ = uuid.Parse(invStr.String)

		if typesStr.Valid {
			json.Unmarshal([]byte(typesStr.String), &ioc.ThreatTypes)
		}

		iocs = append(iocs, ioc)
	}

	return iocs, rows.Err()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
