package api

import (
	"github.com/gofiber/fiber/v2"
)

// ListCampaigns handles GET /campaigns
func ListCampaigns(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"campaigns": []interface{}{},
		"total":     0,
	})
}

// GetCampaign handles GET /campaigns/:id
func GetCampaign(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"id":          c.Params("id"),
		"name":        "Example Campaign",
		"description": "Sample campaign data",
	})
}

// LinkToCampaign handles POST /campaigns/:id/link
func LinkToCampaign(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"linked": true,
	})
}

// GetAnalyticsSummary handles GET /analytics/summary
func GetAnalyticsSummary(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"total_investigations": 0,
		"phishing_detected":    0,
		"false_positives":      0,
		"avg_confidence":       0.0,
		"top_threat_types":     []string{},
	})
}

// GetTrendAnalysis handles GET /analytics/trends
func GetTrendAnalysis(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"daily_trends":   []interface{}{},
		"weekly_summary": map[string]interface{}{},
	})
}
