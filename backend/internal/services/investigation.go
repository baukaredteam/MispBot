package services

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"phishguard/internal/ai"
	"phishguard/internal/database"
	"phishguard/internal/models"
	"phishguard/internal/parsers"
	"phishguard/internal/privacy"
)

type InvestigationService struct {
	db           *database.Database
	emailParser  *parsers.EmailParser
	aiOrchestrator *ai.Orchestrator
	privGateway  *privacy.PrivacyGateway
}

func NewInvestigationService(db *database.Database, parser *parsers.EmailParser, aiOrch *ai.Orchestrator, priv *privacy.PrivacyGateway) *InvestigationService {
	return &InvestigationService{
		db:           db,
		emailParser:  parser,
		aiOrchestrator: aiOrch,
		privGateway:  priv,
	}
}

// CreateInvestigation creates a new investigation from email data
func (s *InvestigationService) CreateInvestigation(tenantID, analystID string, emailData []byte) (*models.Investigation, error) {
	// Parse email locally - NEVER send raw EML externally
	parsedEmail, err := s.emailParser.ParseEmail(emailData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse email: %w", err)
	}

	// Apply privacy masking before any processing
	sensitivityLevel := s.privGateway.AnalyzeSensitivity(parsedEmail.Body.PlainText + parsedEmail.Body.HTML)
	
	// Mask sensitive data in extracted content
	maskedSubject, _, _ := s.privGateway.MaskAndTokenize(parsedEmail.Headers.Subject)
	maskedSenderName, _, _ := s.privGateway.MaskAndTokenize(parsedEmail.Headers.From.Name)

	// Create investigation record
	inv := &models.Investigation{
		ID:              uuid.New(),
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
		TenantID:        tenantID,
		AnalystID:       analystID,
		Status:          models.StatusPending,
		ThreatLevel:     models.ThreatNone,
		ConfidenceScore: 0.0,
		
		// Store only metadata and masked content
		Subject:         maskedSubject,
		SenderEmail:     parsedEmail.Headers.From.Address, // Email addresses are IOCs, keep for analysis
		SenderName:      maskedSenderName,
		RecipientCount:  len(parsedEmail.Headers.To),
		SentAt:          parsedEmail.Headers.Date,
		
		SPFResult:       parsedEmail.AuthResults.SPF.Result,
		DKIMResult:      parsedEmail.AuthResults.DKIM.Result,
		DMARCResult:     parsedEmail.AuthResults.DMARC.Result,
		
		SensitivityLevel: sensitivityLevel.String(),
		DataMasked:       true,
	}

	// Save to database
	if err := s.saveInvestigation(inv); err != nil {
		return nil, err
	}

	// Extract and save IOCs
	if err := s.extractAndSaveIOCs(inv.ID, parsedEmail); err != nil {
		// Log but don't fail - IOC extraction is secondary
		fmt.Printf("Warning: IOC extraction failed: %v\n", err)
	}

	// Save attachments metadata
	if err := s.saveAttachments(inv.ID, parsedEmail.Attachments); err != nil {
		fmt.Printf("Warning: attachment save failed: %v\n", err)
	}

	return inv, nil
}

// Analyze performs AI-assisted analysis on an investigation
func (s *InvestigationService) Analyze(ctx context.Context, invID uuid.UUID) (*models.Investigation, *ai.AnalysisOutput, error) {
	// Get investigation
	inv, err := s.getInvestigation(invID)
	if err != nil {
		return nil, nil, err
	}

	// Get IOCs for context
	iocs, err := s.getIOCs(invID)
	if err != nil {
		return nil, nil, err
	}

	// Build sanitized input for AI - structured JSON only, NO raw content
	input := ai.AnalysisInput{
		InvestigationID:   invID.String(),
		SPFResult:         inv.SPFResult,
		DKIMResult:        inv.DKIMResult,
		DMARCResult:       inv.DMARCResult,
		ReplyToMismatch:   false, // Would need to compare From vs Reply-To
		UrgencyScore:      s.calculateUrgencyScore(inv, iocs),
		CredentialHarvest: s.detectCredentialHarvest(iocs),
		BrandImpersonation: s.detectBrandImpersonation(iocs),
		LinkCount:         len(iocs),
		AttachmentCount:   0, // Would need to fetch attachments
		SuspiciousLinks:   s.identifySuspiciousLinks(iocs),
		HeaderAnomalies:   s.identifyHeaderAnomalies(inv),
	}

	// Call AI orchestrator with sanitized input
	output, err := s.aiOrchestrator.AnalyzePhishing(ctx, input)
	if err != nil {
		return nil, nil, fmt.Errorf("AI analysis failed: %w", err)
	}

	// Update investigation with results
	inv.Status = models.StatusReviewing
	inv.ThreatLevel = output.ThreatLevel
	inv.ConfidenceScore = output.ConfidenceScore
	inv.Verdict = output.Verdict
	inv.MITREATTCK = output.MITREATTCK
	inv.D3FEND = output.D3FEND
	
	// Convert attack chain
	for _, step := range output.AttackChain {
		inv.AttackChain = append(inv.AttackChain, models.AttackStep(step))
	}

	// Save updated investigation
	if err := s.saveInvestigation(inv); err != nil {
		return nil, nil, err
	}

	// Update IOC threat scores based on AI analysis
	if err := s.updateIOCThreatScores(invID, output); err != nil {
		fmt.Printf("Warning: IOC score update failed: %v\n", err)
	}

	return inv, output, nil
}

func (s *InvestigationService) saveInvestigation(inv *models.Investigation) error {
	query := `INSERT OR REPLACE INTO investigations 
		(id, tenant_id, analyst_id, status, threat_level, confidence_score,
		 subject, sender_email, sender_name, recipient_count, sent_at,
		 spf_result, dkim_result, dmarc_result, verdict, attack_chain,
		 mitre_attack, d3fend, sensitivity_level, data_masked, campaign_id,
		 created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	attackChainJSON := "[]" // Would serialize inv.AttackChain to JSON
	mitreJSON := "[]"       // Would serialize inv.MITREATTCK to JSON
	d3fendJSON := "[]"      // Would serialize inv.D3FEND to JSON

	_, err := s.db.DB().Exec(query,
		inv.ID.String(), inv.TenantID, inv.AnalystID,
		inv.Status, inv.ThreatLevel, inv.ConfidenceScore,
		inv.Subject, inv.SenderEmail, inv.SenderName,
		inv.RecipientCount, inv.SentAt,
		inv.SPFResult, inv.DKIMResult, inv.DMARCResult,
		inv.Verdict, attackChainJSON, mitreJSON, d3fendJSON,
		inv.SensitivityLevel, inv.DataMasked, inv.CampaignID,
		inv.CreatedAt, inv.UpdatedAt,
	)

	return err
}

func (s *InvestigationService) getInvestigation(id uuid.UUID) (*models.Investigation, error) {
	query := `SELECT id, tenant_id, analyst_id, status, threat_level, confidence_score,
		subject, sender_email, sender_name, recipient_count, sent_at,
		spf_result, dkim_result, dmarc_result, verdict, sensitivity_level,
		data_masked, campaign_id, created_at, updated_at
		FROM investigations WHERE id = ?`

	row := s.db.DB().QueryRow(query, id.String())
	
	inv := &models.Investigation{}
	var idStr, campaignIDStr sql.NullString
	
	err := row.Scan(
		&idStr, &inv.TenantID, &inv.AnalystID, &inv.Status, &inv.ThreatLevel,
		&inv.ConfidenceScore, &inv.Subject, &inv.SenderEmail, &inv.SenderName,
		&inv.RecipientCount, &inv.SentAt, &inv.SPFResult, &inv.DKIMResult,
		&inv.DMARCResult, &inv.Verdict, &inv.SensitivityLevel, &inv.DataMasked,
		&campaignIDStr, &inv.CreatedAt, &inv.UpdatedAt,
	)
	
	if err != nil {
		return nil, err
	}
	
	inv.ID, _ = uuid.Parse(idStr.String)
	if campaignIDStr.Valid {
		cid, _ := uuid.Parse(campaignIDStr.String)
		inv.CampaignID = &cid
	}
	
	return inv, nil
}

func (s *InvestigationService) extractAndSaveIOCs(invID uuid.UUID, parsed *parsers.ParsedEmail) error {
	now := time.Now().UTC()
	
	insertQuery := `INSERT OR IGNORE INTO iocs 
		(id, investigation_id, type, value, normalized, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)`

	// Process domains
	for _, domain := range parsed.IOCs.Domains {
		id := uuid.New()
		normalized := strings.ToLower(domain)
		_, err := s.db.DB().Exec(insertQuery,
			id.String(), invID.String(), models.IOCTypeDomain,
			domain, normalized, now, now,
		)
		if err != nil {
			return err
		}
	}

	// Process IPs
	for _, ip := range parsed.IOCs.IPs {
		id := uuid.New()
		_, err := s.db.DB().Exec(insertQuery,
			id.String(), invID.String(), models.IOCTypeIP,
			ip, ip, now, now,
		)
		if err != nil {
			return err
		}
	}

	// Process URLs
	for _, url := range parsed.IOCs.URLs {
		id := uuid.New()
		normalized := strings.ToLower(url)
		_, err := s.db.DB().Exec(insertQuery,
			id.String(), invID.String(), models.IOCTypeURL,
			url, normalized, now, now,
		)
		if err != nil {
			return err
		}
	}

	// Process emails
	for _, email := range parsed.IOCs.Emails {
		id := uuid.New()
		normalized := strings.ToLower(email)
		_, err := s.db.DB().Exec(insertQuery,
			id.String(), invID.String(), models.IOCTypeEmail,
			email, normalized, now, now,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *InvestigationService) saveAttachments(invID uuid.UUID, attachments []parsers.AttachmentInfo) error {
	query := `INSERT INTO attachments 
		(id, investigation_id, filename, original_filename, size, mime_type,
		 md5, sha1, sha256, encrypted)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	for _, att := range attachments {
		_, err := s.db.DB().Exec(query,
			att.ID.String(), invID.String(), att.Filename, att.OriginalName,
			att.Size, att.ContentType, att.MD5, att.SHA1, att.SHA256, true,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *InvestigationService) calculateUrgencyScore(inv *models.Investigation, iocs []models.IOC) int {
	score := 0

	// Authentication failures increase urgency
	if inv.SPFResult == "fail" {
		score += 20
	}
	if inv.DKIMResult == "fail" {
		score += 20
	}
	if inv.DMARCResult == "fail" {
		score += 30
	}

	// High threat score IOCs increase urgency
	for _, ioc := range iocs {
		if ioc.ThreatScore > 50 {
			score += 10
		}
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

func (s *InvestigationService) detectCredentialHarvest(iocs []models.IOC) bool {
	// Look for known credential harvesting indicators
	harvestKeywords := []string{"login", "signin", "account", "verify", "password", "credential"}
	
	for _, ioc := range iocs {
		lowerValue := strings.ToLower(ioc.Value)
		for _, keyword := range harvestKeywords {
			if strings.Contains(lowerValue, keyword) {
				return true
			}
		}
	}
	
	return false
}

func (s *InvestigationService) detectBrandImpersonation(iocs []models.IOC) string {
	brands := map[string][]string{
		"Microsoft": {"microsoft.com", "office365.com", "outlook.com"},
		"Google":    {"google.com", "gmail.com"},
		"Apple":     {"apple.com", "icloud.com"},
		"Amazon":    {"amazon.com", "aws.amazon.com"},
	}

	for _, ioc := range iocs {
		if ioc.Type == models.IOCTypeDomain {
			for brand, legitDomains := range brands {
				for _, legit := range legitDomains {
					similarity := privacy.CalculateSimilarity(ioc.Normalized, legit)
					if similarity > 0.7 && ioc.Normalized != legit {
						return brand
					}
				}
			}
		}
	}

	return ""
}

func (s *InvestigationService) identifySuspiciousLinks(iocs []models.IOC) []ai.SuspiciousLinkInfo {
	var suspicious []ai.SuspiciousLinkInfo

	for _, ioc := range iocs {
		if ioc.Type == models.IOCTypeURL {
			info := ai.SuspiciousLinkInfo{
				URL: ioc.Value,
			}

			if ioc.ThreatScore > 0 {
				info.Reasons = append(info.Reasons, fmt.Sprintf("threat_score:%d", ioc.ThreatScore))
			}

			// Check for suspicious patterns
			if strings.Contains(ioc.Value, "@") {
				info.Reasons = append(info.Reasons, "contains @ symbol")
			}

			if len(info.Reasons) > 0 {
				suspicious = append(suspicious, info)
			}
		}
	}

	return suspicious
}

func (s *InvestigationService) identifyHeaderAnomalies(inv *models.Investigation) []string {
	var anomalies []string

	if inv.SPFResult == "fail" || inv.SPFResult == "softfail" {
		anomalies = append(anomalies, "SPF authentication failed")
	}

	if inv.DKIMResult == "fail" {
		anomalies = append(anomalies, "DKIM signature verification failed")
	}

	if inv.DMARCResult == "fail" {
		anomalies = append(anomalies, "DMARC policy violation")
	}

	return anomalies
}

func (s *InvestigationService) getIOCs(invID uuid.UUID) ([]models.IOC, error) {
	query := `SELECT id, investigation_id, type, value, normalized, threat_score,
		threat_types, country, asn, blocked, whitelisted, first_seen, last_seen
		FROM iocs WHERE investigation_id = ?`

	rows, err := s.db.DB().Query(query, invID.String())
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
			// Parse JSON array of threat types
			ioc.ThreatTypes = []string{} // Would parse JSON
		}

		iocs = append(iocs, ioc)
	}

	return iocs, rows.Err()
}

func (s *InvestigationService) updateIOCThreatScores(invID uuid.UUID, output *ai.AnalysisOutput) error {
	// Increase threat scores based on AI verdict
	scoreIncrease := 0
	switch output.Verdict {
	case "phishing":
		scoreIncrease = 40
	case "malware":
		scoreIncrease = 50
	case "suspicious":
		scoreIncrease = 20
	}

	if scoreIncrease == 0 {
		return nil
	}

	query := `UPDATE iocs SET threat_score = MIN(threat_score + ?, 100),
		last_seen = ? WHERE investigation_id = ?`

	_, err := s.db.DB().Exec(query, scoreIncrease, time.Now().UTC(), invID.String())
	return err
}

// Helper to convert SensitivityLevel to string
func (sl privacy.SensitivityLevel) String() string {
	switch sl {
	case privacy.SensitivityPublic:
		return "public"
	case privacy.SensitivityInternal:
		return "internal"
	case privacy.SensitivityConfidential:
		return "confidential"
	case privacy.SensitivityRestricted:
		return "restricted"
	default:
		return "unknown"
	}
}
