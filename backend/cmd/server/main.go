package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"

	"phishguard/internal/ai"
	"phishguard/internal/api"
	"phishguard/internal/config"
	"phishguard/internal/database"
	"phishguard/internal/parsers"
	"phishguard/internal/privacy"
	"phishguard/internal/services"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize privacy gateway
	privGateway, err := privacy.NewPrivacyGateway(cfg.Security.EncryptionKey)
	if err != nil {
		log.Fatalf("Failed to initialize privacy gateway: %v", err)
	}

	// Initialize database
	db, err := database.NewDatabase(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Initialize AI orchestrator
	aiOrchestrator := ai.NewOrchestrator(&cfg.AI, privGateway)

	// Initialize email parser
	emailParser := parsers.NewEmailParser(cfg.Security.MaxUploadSize, cfg.Security.AllowedMimeTypes)

	// Initialize services
	investigationService := services.NewInvestigationService(db, emailParser, aiOrchestrator, privGateway)
	iocService := services.NewIOCService(db, privGateway)

	// Initialize API handlers
	investigationHandler := api.NewInvestigationHandler(investigationService)
	iocHandler := api.NewIOCHandler(iocService)

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "PhishGuard",
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
		ErrorHandler: customErrorHandler,
	})

	// Middleware
	app.Use(logger.New(logger.Config{
		Format:     "${time} | ${status} | ${latency} | ${ip} | ${method} | ${path} | ${error}\n",
		TimeFormat: "2006-01-02 15:04:05",
	}))
	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://localhost:3000",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Accept,Authorization,X-Tenant-ID",
	}))

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":    "healthy",
			"timestamp": time.Now().UTC(),
			"version":   "1.0.0",
		})
	})

	// API routes
	v1 := app.Group("/api/v1")

	// Investigation routes
	investigations := v1.Group("/investigations")
	investigations.Post("/", investigationHandler.CreateInvestigation)
	investigations.Get("/", investigationHandler.ListInvestigations)
	investigations.Get("/:id", investigationHandler.GetInvestigation)
	investigations.Put("/:id/status", investigationHandler.UpdateStatus)
	investigations.Post("/:id/analyze", investigationHandler.Analyze)
	investigations.Delete("/:id", investigationHandler.DeleteInvestigation)

	// IOC routes
	iocs := v1.Group("/iocs")
	iocs.Get("/", iocHandler.ListIOCs)
	iocs.Get("/:id", iocHandler.GetIOC)
	iocs.Post("/:id/block", iocHandler.BlockIOC)
	iocs.Post("/:id/whitelist", iocHandler.WhitelistIOC)
	iocs.Get("/search", iocHandler.SearchIOCs)

	// Campaign routes
	campaigns := v1.Group("/campaigns")
	campaigns.Get("/", api.ListCampaigns)
	campaigns.Get("/:id", api.GetCampaign)
	campaigns.Post("/:id/link", api.LinkToCampaign)

	// Analytics routes
	analytics := v1.Group("/analytics")
	analytics.Get("/summary", api.GetAnalyticsSummary)
	analytics.Get("/trends", api.GetTrendAnalysis)

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down server...")
		cancel()
	}()

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		addr := cfg.ServerAddr()
		log.Printf("Starting PhishGuard server on %s", addr)
		if err := app.Listen(addr); err != nil {
			serverErr <- err
		}
	}()

	// Wait for shutdown signal or server error
	select {
	case <-ctx.Done():
		log.Println("Graceful shutdown initiated")
	case err := <-serverErr:
		log.Fatalf("Server error: %v", err)
	}

	// Cleanup
	if err := app.ShutdownWithTimeout(30 * time.Second); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}

	log.Println("PhishGuard server stopped")
}

func customErrorHandler(c *fiber.Ctx, err error) error {
	// Default error status code
	code := fiber.StatusInternalServerError

	// Check if it's a Fiber error
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	// Log the error
	log.Printf("Error: %v | Path: %s | Method: %s", err, c.Path(), c.Method())

	// Return structured error response
	return c.Status(code).JSON(fiber.Map{
		"error": fiber.Map{
			"code":    code,
			"message": err.Error(),
		},
		"request_id": c.GetRespHeader("X-Request-ID"),
	})
}
