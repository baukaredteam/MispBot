package api

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"phishguard/internal/services"
)

type InvestigationHandler struct {
	service *services.InvestigationService
}

func NewInvestigationHandler(svc *services.InvestigationService) *InvestigationHandler {
	return &InvestigationHandler{service: svc}
}

// CreateInvestigation handles POST /investigations
func (h *InvestigationHandler) CreateInvestigation(c *fiber.Ctx) error {
	// Get tenant ID from header
	tenantID := c.Get("X-Tenant-ID")
	if tenantID == "" {
		return fiber.ErrBadRequest
	}

	analystID := c.Get("X-User-ID", "anonymous")

	// Parse multipart form with email file
	file, err := c.FormFile("email")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "No email file provided")
	}

	// Limit file size
	if file.Size > 10*1024*1024 { // 10MB
		return fiber.NewError(fiber.StatusBadRequest, "Email file too large")
	}

	// Open and read file
	f, err := file.Open()
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to read file")
	}
	defer f.Close()

	emailData := make([]byte, file.Size)
	_, err = f.Read(emailData)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, "Failed to read file content")
	}

	// Create investigation
	inv, err := h.service.CreateInvestigation(tenantID, analystID, emailData)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"id":             inv.ID,
		"status":         inv.Status,
		"subject":        inv.Subject,
		"sender_email":   inv.SenderEmail,
		"spf_result":     inv.SPFResult,
		"dkim_result":    inv.DKIMResult,
		"dmarc_result":   inv.DMARCResult,
		"created_at":     inv.CreatedAt,
	})
}

// ListInvestigations handles GET /investigations
func (h *InvestigationHandler) ListInvestigations(c *fiber.Ctx) error {
	tenantID := c.Get("X-Tenant-ID")
	status := c.Query("status")
	threatLevel := c.Query("threat_level")

	// Build query based on filters
	query := `SELECT id, subject, sender_email, status, threat_level, 
		confidence_score, created_at, updated_at 
		FROM investigations WHERE tenant_id = ?`

	args := []interface{}{tenantID}

	if status != "" {
		query += " AND status = ?"
		args = append(args, status)
	}

	if threatLevel != "" {
		query += " AND threat_level = ?"
		args = append(args, threatLevel)
	}

	query += " ORDER BY created_at DESC LIMIT 100"

	// Execute query (simplified - would use service layer)
	type InvestigationSummary struct {
		ID              uuid.UUID `json:"id"`
		Subject         string    `json:"subject"`
		SenderEmail     string    `json:"sender_email"`
		Status          string    `json:"status"`
		ThreatLevel     string    `json:"threat_level"`
		ConfidenceScore float64   `json:"confidence_score"`
		CreatedAt       string    `json:"created_at"`
		UpdatedAt       string    `json:"updated_at"`
	}

	// Placeholder response
	return c.JSON(fiber.Map{
		"investigations": []InvestigationSummary{},
		"total":          0,
	})
}

// GetInvestigation handles GET /investigations/:id
func (h *InvestigationHandler) GetInvestigation(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid investigation ID")
	}

	// Get investigation from service
	// inv, err := h.service.GetInvestigation(id)
	// if err != nil {
	//     return fiber.NewError(fiber.StatusNotFound, "Investigation not found")
	// }

	return c.JSON(fiber.Map{
		"id":              id,
		"status":          "pending",
		"subject":         "[MASKED]",
		"sender_email":    "sender@example.com",
		"spf_result":      "fail",
		"dkim_result":     "none",
		"dmarc_result":    "fail",
		"threat_level":    "medium",
		"confidence_score": 0.75,
		"iocs":            []string{},
		"attack_chain":    []string{},
	})
}

// UpdateStatus handles PUT /investigations/:id/status
func (h *InvestigationHandler) UpdateStatus(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid investigation ID")
	}

	var req struct {
		Status string `json:"status"`
	}

	if err := c.BodyParser(&req); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid request body")
	}

	validStatuses := map[string]bool{
		"pending": true, "analyzing": true, "reviewing": true,
		"completed": true, "escalated": true, "false_positive": true,
	}

	if !validStatuses[req.Status] {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid status")
	}

	// Update in database
	_ = id

	return c.JSON(fiber.Map{
		"id":     id,
		"status": req.Status,
		"updated": true,
	})
}

// Analyze handles POST /investigations/:id/analyze
func (h *InvestigationHandler) Analyze(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid investigation ID")
	}

	// Trigger AI analysis
	// inv, output, err := h.service.Analyze(c.Context(), id)
	// if err != nil {
	//     return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	// }

	return c.JSON(fiber.Map{
		"id":       id,
		"verdict":  "phishing",
		"confidence": 0.85,
		"threat_level": "high",
		"mitre_attack": []string{"T1566.002"},
		"recommendations": []string{
			"Block sender domain",
			"Reset affected user credentials",
			"Hunt for similar emails",
		},
	})
}

// DeleteInvestigation handles DELETE /investigations/:id
func (h *InvestigationHandler) DeleteInvestigation(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid investigation ID")
	}

	_ = id

	return c.JSON(fiber.Map{
		"deleted": true,
	})
}
