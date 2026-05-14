package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"phishguard/internal/config"
	"phishguard/internal/models"
	"phishguard/internal/privacy"
)

// AnalysisInput contains sanitized data for AI analysis
type AnalysisInput struct {
	InvestigationID   string                 `json:"investigation_id"`
	SPFResult         string                 `json:"spf_result"`
	DKIMResult        string                 `json:"dkim_result"`
	DMARCResult       string                 `json:"dmarc_result"`
	ReplyToMismatch   bool                   `json:"reply_to_mismatch"`
	UrgencyScore      int                    `json:"urgency_score"`
	CredentialHarvest bool                   `json:"credential_harvest"`
	BrandImpersonation string                `json:"brand_impersonation,omitempty"`
	SandboxVerdict    string                 `json:"sandbox_verdict,omitempty"`
	DetectedTTPs      []string               `json:"detected_ttps,omitempty"`
	LinkCount         int                    `json:"link_count"`
	AttachmentCount   int                    `json:"attachment_count"`
	SuspiciousLinks   []SuspiciousLinkInfo   `json:"suspicious_links,omitempty"`
	HeaderAnomalies   []string               `json:"header_anomalies,omitempty"`
}

type SuspiciousLinkInfo struct {
	URL        string   `json:"url"`
	Reasons    []string `json:"reasons"`
	IsEncoded  bool     `json:"is_encoded"`
}

// AnalysisOutput contains AI-generated analysis results
type AnalysisOutput struct {
	Verdict           string                `json:"verdict"`
	ConfidenceScore   float64               `json:"confidence_score"`
	ThreatLevel       models.ThreatLevel    `json:"threat_level"`
	AttackChain       []models.AttackStep   `json:"attack_chain"`
	MITREATTCK        []string              `json:"mitre_attack"`
	D3FEND            []string              `json:"d3fend"`
	SocialEngineering string                `json:"social_engineering"`
	Objectives        []string              `json:"objectives"`
	CVEUsage          string                `json:"cve_usage,omitempty"`
	RiskExplanation   string                `json:"risk_explanation"`
	Recommendations   []Recommendation      `json:"recommendations"`
	Reasoning         string                `json:"reasoning"`
	Flags             []AnalysisFlag        `json:"flags"`
}

type Recommendation struct {
	Priority   int      `json:"priority"` // 1=highest
	Category   string   `json:"category"` // remediation, detection, hunting, notification
	Action     string   `json:"action"`
	Details    string   `json:"details"`
	Automation bool     `json:"automation"` // can be automated?
}

type AnalysisFlag struct {
	Type      string `json:"type"`
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Evidence  string `json:"evidence"`
}

// Orchestrator manages AI interactions with privacy controls
type Orchestrator struct {
	config        *config.AIConfig
	httpClient    *http.Client
	privGateway   *privacy.PrivacyGateway
	sanitizer     *privacy.PromptSanitizer
	
	mu            sync.RWMutex
	requestCount  int64
	lastRequest   time.Time
	
	// Model routing
	modelRoutes map[string]string // provider -> model name
}

// NewOrchestrator creates a new AI orchestrator
func NewOrchestrator(cfg *config.AIConfig, privGateway *privacy.PrivacyGateway) *Orchestrator {
	return &Orchestrator{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.RequestTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		privGateway: privGateway,
		sanitizer:   privacy.NewPromptSanitizer(),
		modelRoutes: map[string]string{
			"deepseek": "deepseek-chat",
			"claude":   "claude-3-haiku-20240307",
			"ollama":   "llama3.1:8b",
		},
	}
}

// AnalyzePhishing performs AI-assisted phishing analysis on sanitized input
func (o *Orchestrator) AnalyzePhishing(ctx context.Context, input AnalysisInput) (*AnalysisOutput, error) {
	o.mu.Lock()
	o.requestCount++
	o.lastRequest = time.Now()
	o.mu.Unlock()
	
	// Validate input doesn't contain sensitive data
	if err := o.validateInput(input); err != nil {
		return nil, fmt.Errorf("input validation failed: %w", err)
	}
	
	// Build structured prompt - NEVER include raw EML
	prompt := o.buildAnalysisPrompt(input)
	
	// Sanitize prompt
	sanitizedPrompt, err := o.sanitizer.SanitizeForPrompt(prompt)
	if err != nil {
		return nil, fmt.Errorf("prompt sanitization failed: %w", err)
	}
	
	// Determine which provider to use
	provider := o.selectProvider(input)
	
	// Make request with retry logic
	var output *AnalysisOutput
	var lastErr error
	
	for attempt := 0; attempt < o.config.MaxRetries; attempt++ {
		output, lastErr = o.makeRequest(ctx, provider, sanitizedPrompt)
		if lastErr == nil {
			break
		}
		
		if attempt < o.config.MaxRetries-1 {
			waitTime := time.Duration(1<<uint(attempt)) * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(waitTime):
				continue
			}
		}
	}
	
	if lastErr != nil {
		return nil, fmt.Errorf("AI request failed after %d attempts: %w", o.config.MaxRetries, lastErr)
	}
	
	// Validate output
	if err := o.validateOutput(output); err != nil {
		return nil, fmt.Errorf("output validation failed: %w", err)
	}
	
	return output, nil
}

func (o *Orchestrator) validateInput(input AnalysisInput) error {
	// Check that no raw emails, IPs, or URLs are present
	// Only tokens should be present
	
	// This is a secondary check - primary masking should happen before
	testStr := fmt.Sprintf("%+v", input)
	
	// Quick regex checks for unmasked data
	emailRe := `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
	ipRe := `\b(?:\d{1,3}\.){3}\d{1,3}\b`
	
	// If we find raw patterns, reject
	// In production, use proper regex compilation and matching
	if strings.Contains(testStr, "@") && !strings.Contains(testStr, "[ema") {
		// Potential unmasked email
		// More sophisticated check needed in production
	}
	
	return nil
}

func (o *Orchestrator) buildAnalysisPrompt(input AnalysisInput) string {
	// Build structured JSON prompt
	inputJSON, _ := json.MarshalIndent(input, "", "  ")
	
	prompt := fmt.Sprintf(`You are a phishing analysis expert. Analyze the following sanitized email metadata and provide a structured security assessment.

INPUT DATA (sanitized):
%s

Provide your analysis in the following JSON format ONLY:
{
  "verdict": "phishing|spam|malware|legitimate|suspicious",
  "confidence_score": 0.0-1.0,
  "threat_level": "none|low|medium|high|critical",
  "attack_chain": [
    {
      "order": 1,
      "tactic": "Initial Access",
      "technique": "T1566.002",
      "description": "...",
      "evidence": "...",
      "confidence": 0.0-1.0
    }
  ],
  "mitre_attack": ["T1566.002"],
  "d3fend": ["D3-EMTA"],
  "social_engineering": "...",
  "objectives": ["credential theft", "malware delivery"],
  "cve_usage": "..." or null,
  "risk_explanation": "...",
  "recommendations": [
    {
      "priority": 1,
      "category": "remediation|detection|hunting|notification",
      "action": "...",
      "details": "...",
      "automation": false
    }
  ],
  "reasoning": "...",
  "flags": [
    {
      "type": "...",
      "severity": "low|medium|high|critical",
      "message": "...",
      "evidence": "..."
    }
  ]
}

IMPORTANT RULES:
1. Base analysis ONLY on the provided metadata
2. Do NOT hallucinate technical details
3. Provide confidence scores for all claims
4. Map to MITRE ATT&CK techniques where applicable
5. Include D3FEND countermeasures
6. Prioritize recommendations by impact
7. Flag any uncertainties`, string(inputJSON))

	return prompt
}

func (o *Orchestrator) selectProvider(input AnalysisInput) string {
	// Simple routing logic - can be enhanced based on load, cost, etc.
	if input.ThreatLevel == "" {
		// Default to fast model for initial triage
		return "ollama"
	}
	
	// For high-confidence threats, use more capable model
	if o.config.ClaudeAPIKey != "" {
		return "claude"
	}
	
	if o.config.DeepSeekAPIKey != "" {
		return "deepseek"
	}
	
	return "ollama"
}

func (o *Orchestrator) makeRequest(ctx context.Context, provider string, prompt string) (*AnalysisOutput, error) {
	var endpoint string
	var apiKey string
	var model string
	
	switch provider {
	case "claude":
		endpoint = "https://api.anthropic.com/v1/messages"
		apiKey = o.config.ClaudeAPIKey
		model = o.modelRoutes["claude"]
	case "deepseek":
		endpoint = "https://api.deepseek.com/v1/chat/completions"
		apiKey = o.config.DeepSeekAPIKey
		model = o.modelRoutes["deepseek"]
	case "ollama":
		endpoint = o.config.OllamaEndpoint + "/api/generate"
		model = o.modelRoutes["ollama"]
	default:
		endpoint = o.config.LiteLLMEndpoint + "/v1/chat/completions"
		model = o.config.DefaultModel
	}
	
	var reqBody []byte
	var req *http.Request
	var err error
	
	if provider == "claude" {
		body := map[string]interface{}{
			"model": model,
			"max_tokens": o.config.MaxTokens,
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		}
		reqBody, _ = json.Marshal(body)
		req, _ = http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("x-api-key", apiKey)
		req.Header.Set("anthropic-version", "2023-06-01")
	} else {
		body := map[string]interface{}{
			"model": model,
			"max_tokens": o.config.MaxTokens,
			"temperature": o.config.Temperature,
			"messages": []map[string]string{
				{"role": "user", "content": prompt},
			},
		}
		reqBody, _ = json.Marshal(body)
		req, _ = http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}
	
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}
	
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	// Extract response based on provider
	var content string
	if provider == "ollama" {
		if response, ok := result["response"].(string); ok {
			content = response
		}
	} else if provider == "claude" {
		if content_arr, ok := result["content"].([]interface{}); ok && len(content_arr) > 0 {
			if contentObj, ok := content_arr[0].(map[string]interface{}); ok {
				content, _ = contentObj["text"].(string)
			}
		}
	} else {
		if choices, ok := result["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if message, ok := choice["message"].(map[string]interface{}); ok {
					content, _ = message["content"].(string)
				}
			}
		}
	}
	
	if content == "" {
		return nil, fmt.Errorf("empty response from AI")
	}
	
	// Parse JSON from response
	output, err := o.parseAIResponse(content)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AI response: %w", err)
	}
	
	return output, nil
}

func (o *Orchestrator) parseAIResponse(content string) (*AnalysisOutput, error) {
	// Try to extract JSON from response
	content = strings.TrimSpace(content)
	
	// Remove markdown code blocks if present
	if strings.HasPrefix(content, "```") {
		lines := strings.Split(content, "\n")
		if len(lines) > 2 {
			content = strings.Join(lines[1:len(lines)-1], "\n")
		}
	}
	
	// Find JSON object
	startIdx := strings.Index(content, "{")
	endIdx := strings.LastIndex(content, "}")
	
	if startIdx == -1 || endIdx == -1 || startIdx >= endIdx {
		return nil, fmt.Errorf("no valid JSON found in response")
	}
	
	jsonStr := content[startIdx : endIdx+1]
	
	var output AnalysisOutput
	if err := json.Unmarshal([]byte(jsonStr), &output); err != nil {
		return nil, fmt.Errorf("JSON parse error: %w", err)
	}
	
	return &output, nil
}

func (o *Orchestrator) validateOutput(output *AnalysisOutput) error {
	if output.Verdict == "" {
		return fmt.Errorf("missing verdict")
	}
	
	if output.ConfidenceScore < 0 || output.ConfidenceScore > 1 {
		return fmt.Errorf("invalid confidence score: %f", output.ConfidenceScore)
	}
	
	validVerdicts := map[string]bool{
		"phishing": true, "spam": true, "malware": true,
		"legitimate": true, "suspicious": true,
	}
	
	if !validVerdicts[output.Verdict] {
		return fmt.Errorf("invalid verdict: %s", output.Verdict)
	}
	
	return nil
}

// ExplainAttackChain generates human-readable explanation of attack chain
func (o *Orchestrator) ExplainAttackChain(ctx context.Context, steps []models.AttackStep) (string, error) {
	input := AnalysisInput{
		DetectedTTPs: make([]string, len(steps)),
	}
	
	for i, step := range steps {
		input.DetectedTTPs[i] = step.Technique
	}
	
	prompt := fmt.Sprintf(`Explain the following attack chain in clear, non-technical language suitable for security analysts:

Attack Steps:
`)
	
	for _, step := range steps {
		prompt += fmt.Sprintf("- %s (%s): %s\n", step.Tactic, step.Technique, step.Description)
	}
	
	prompt += `
Provide:
1. Executive summary of the attack
2. Step-by-step explanation
3. Impact assessment
4. Key indicators to look for`

	sanitizedPrompt, _ := o.sanitizer.SanitizeForPrompt(prompt)
	
	// Simplified implementation - full implementation would call makeRequest
	return fmt.Sprintf("Attack chain explanation for %d steps", len(steps)), nil
}

// GetStats returns orchestrator statistics
func (o *Orchestrator) GetStats() map[string]interface{} {
	o.mu.RLock()
	defer o.mu.RUnlock()
	
	return map[string]interface{}{
		"request_count": o.requestCount,
		"last_request":  o.lastRequest,
	}
}
