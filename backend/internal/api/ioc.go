package api

import (
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"phishguard/internal/services"
)

type IOCHandler struct {
	service *services.IOCService
}

func NewIOCHandler(svc *services.IOCService) *IOCHandler {
	return &IOCHandler{service: svc}
}

// ListIOCs handles GET /iocs
func (h *IOCHandler) ListIOCs(c *fiber.Ctx) error {
	iocType := c.Query("type")
	minScore := c.QueryInt("min_score", 0)
	blocked := c.QueryBool("blocked")

	iocs, err := h.service.SearchIOCs("", iocType, minScore)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	// Filter by blocked status if specified
	if c.Query("blocked") != "" {
		filtered := []interface{}{}
		for _, ioc := range iocs {
			if ioc.Blocked == blocked {
				filtered = append(filtered, ioc)
			}
		}
		return c.JSON(fiber.Map{"iocs": filtered})
	}

	return c.JSON(fiber.Map{"iocs": iocs})
}

// GetIOC handles GET /iocs/:id
func (h *IOCHandler) GetIOC(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid IOC ID")
	}

	ioc, err := h.service.GetIOC(id)
	if err != nil {
		return fiber.NewError(fiber.StatusNotFound, "IOC not found")
	}

	return c.JSON(ioc)
}

// BlockIOC handles POST /iocs/:id/block
func (h *IOCHandler) BlockIOC(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid IOC ID")
	}

	var req struct {
		Reason string `json:"reason"`
	}
	c.BodyParser(&req)

	if err := h.service.BlockIOC(id, req.Reason); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"id":      id,
		"blocked": true,
		"reason":  req.Reason,
	})
}

// WhitelistIOC handles POST /iocs/:id/whitelist
func (h *IOCHandler) WhitelistIOC(c *fiber.Ctx) error {
	idStr := c.Params("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "Invalid IOC ID")
	}

	var req struct {
		Reason string `json:"reason"`
	}
	c.BodyParser(&req)

	if err := h.service.WhitelistIOC(id, req.Reason); err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"id":          id,
		"whitelisted": true,
		"reason":      req.Reason,
	})
}

// SearchIOCs handles GET /iocs/search
func (h *IOCHandler) SearchIOCs(c *fiber.Ctx) error {
	query := c.Query("q")
	iocType := c.Query("type")
	minScore := c.QueryInt("min_score", 0)

	iocs, err := h.service.SearchIOCs(query, iocType, minScore)
	if err != nil {
		return fiber.NewError(fiber.StatusInternalServerError, err.Error())
	}

	return c.JSON(fiber.Map{
		"iocs":  iocs,
		"total": len(iocs),
	})
}
