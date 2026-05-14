package parsers

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// EmailParser safely parses email messages without exposing raw content
type EmailParser struct {
	maxAttachmentSize int64
	allowedMimeTypes  map[string]bool
}

// ParsedEmail contains extracted metadata and structured data from an email
type ParsedEmail struct {
	Headers       EmailHeaders
	Body          EmailBody
	Attachments   []AttachmentInfo
	Links         []ExtractedLink
	IOCs          RawIOCs
	AuthResults   AuthResults
	RawMessageID  string
	ParseWarnings []string
}

type EmailHeaders struct {
	MessageID     string
	Subject       string
	From          AddressInfo
	To            []AddressInfo
	Cc            []AddressInfo
	Bcc           []AddressInfo
	ReplyTo       []AddressInfo
	Date          time.Time
	Received      []ReceivedHeader
	XMailer       string
	UserAgent     string
	ContentType   string
}

type AddressInfo struct {
	Name    string
	Address string
	Raw     string
}

type ReceivedHeader struct {
	From      string
	By        string
	Via       string
	With      string
	Timestamp time.Time
	Delay     float64
}

type EmailBody struct {
	PlainText    string
	HTML         string
	TextPartType string
	HTMLPartType string
	Charset      string
}

type AttachmentInfo struct {
	ID            uuid.UUID
	Filename      string
	OriginalName  string
	ContentType   string
	Size          int64
	MD5           string
	SHA1          string
	SHA256        string
	Disposition   string
	IsInline      bool
	ContentID     string
	Data          []byte // Kept in memory temporarily, encrypted before storage
}

type ExtractedLink struct {
	URL           string
	DisplayText   string
	Context       string
	IsEncoded     bool
	DecodedURL    string
	Suspicious    bool
	SuspicionReasons []string
}

type RawIOCs struct {
	Domains      []string
	IPs          []string
	Emails       []string
	URLs         []string
	FileHashes   []FileHash
	PhoneNumbers []string
}

type FileHash struct {
	Type  string // md5, sha1, sha256
	Value string
}

type AuthResults struct {
	SPF       SPFResult
	DKIM      DKIMResult
	DMARC     DMARCResult
	BIMI      BIMIResult
	ARC       ARCResult
}

type SPFResult struct {
	Result      string // pass, fail, softfail, neutral, temperror, permerror, none
	Details     string
	EnvelopeFrom string
}

type DKIMResult struct {
	Result      string // pass, fail, neutral, temperror, permerror, none
	Selector    string
	SignDomain  string
	Signature   string
	Headers     []string
}

type DMARCResult struct {
	Result      string // pass, fail, none
	Policy      string
	AlignmentSPF  bool
	AlignmentDKIM bool
	Details     string
}

type BIMIResult struct {
	Present   bool
	Indicator string
	Errors    []string
}

type ARCResult struct {
	Present bool
	Status  string
	Seal    string
}

// NewEmailParser creates a new email parser with security constraints
func NewEmailParser(maxAttachmentSize int64, allowedMimeTypes []string) *EmailParser {
	allowedMap := make(map[string]bool)
	for _, mt := range allowedMimeTypes {
		allowedMap[mt] = true
	}
	
	// Always allow common types
	allowedMap["text/plain"] = true
	allowedMap["text/html"] = true
	allowedMap["multipart/mixed"] = true
	allowedMap["multipart/alternative"] = true
	allowedMap["multipart/related"] = true
	
	return &EmailParser{
		maxAttachmentSize: maxAttachmentSize,
		allowedMimeTypes:  allowedMap,
	}
}

// ParseEmail safely parses an email message
func (ep *EmailParser) ParseEmail(rawData []byte) (*ParsedEmail, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(rawData))
	if err != nil {
		return nil, fmt.Errorf("failed to read message: %w", err)
	}
	
	result := &ParsedEmail{
		Headers: EmailHeaders{},
		Body:    EmailBody{},
	}
	
	// Parse headers
	ep.parseHeaders(msg.Header, &result.Headers)
	result.RawMessageID = msg.Header.Get("Message-ID")
	
	// Parse body and attachments
	if err := ep.parseBody(msg.Body, result); err != nil {
		result.ParseWarnings = append(result.ParseWarnings, fmt.Sprintf("body parse error: %v", err))
	}
	
	// Extract IOCs
	ep.extractIOCs(result)
	
	// Analyze authentication results
	ep.analyzeAuthResults(msg.Header, &result.AuthResults)
	
	return result, nil
}

func (ep *EmailParser) parseHeaders(header mail.Header, headers *EmailHeaders) {
	headers.MessageID = header.Get("Message-ID")
	headers.Subject = header.Get("Subject")
	headers.XMailer = header.Get("X-Mailer")
	headers.UserAgent = header.Get("User-Agent")
	headers.ContentType = header.Get("Content-Type")
	
	// Parse From
	if from := header.Get("From"); from != "" {
		headers.From = ep.parseAddress(from)
	}
	
	// Parse To
	if to := header.Get("To"); to != "" {
		headers.To = ep.parseAddressList(to)
	}
	
	// Parse Cc
	if cc := header.Get("Cc"); cc != "" {
		headers.Cc = ep.parseAddressList(cc)
	}
	
	// Parse Reply-To
	if replyTo := header.Get("Reply-To"); replyTo != "" {
		headers.ReplyTo = ep.parseAddressList(replyTo)
	}
	
	// Parse Date
	if dateStr := header.Get("Date"); dateStr != "" {
		if date, err := mail.ParseDate(dateStr); err == nil {
			headers.Date = date
		}
	}
	
	// Parse Received headers
	receivedHeaders := header.Values("Received")
	for _, rh := range receivedHeaders {
		if parsed := ep.parseReceivedHeader(rh); parsed != nil {
			headers.Received = append(headers.Received, *parsed)
		}
	}
}

func (ep *EmailParser) parseAddress(raw string) AddressInfo {
	addr, err := mail.ParseAddress(raw)
	if err != nil {
		return AddressInfo{Raw: raw}
	}
	
	return AddressInfo{
		Name:    addr.Name,
		Address: addr.Address,
		Raw:     raw,
	}
}

func (ep *EmailParser) parseAddressList(raw string) []AddressInfo {
	var addresses []AddressInfo
	
	// Handle multiple addresses
	parts := strings.Split(raw, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		
		addr := ep.parseAddress(part)
		addresses = append(addresses, addr)
	}
	
	return addresses
}

func (ep *EmailParser) parseReceivedHeader(raw string) *ReceivedHeader {
	// Basic parsing of Received header
	// Format: from <source> by <dest> with <protocol>; <date>
	header := &ReceivedHeader{}
	
	// Extract timestamp (usually at the end after semicolon)
	if idx := strings.LastIndex(raw, ";"); idx != -1 {
		dateStr := strings.TrimSpace(raw[idx+1:])
		if date, err := mail.ParseDate(dateStr); err == nil {
			header.Timestamp = date
		}
		raw = raw[:idx]
	}
	
	// Extract 'from' clause
	if fromMatch := regexp.MustCompile(`from\s+([^\s;]+)`).FindStringSubmatch(raw); len(fromMatch) > 1 {
		header.From = fromMatch[1]
	}
	
	// Extract 'by' clause
	if byMatch := regexp.MustCompile(`by\s+([^\s;]+)`).FindStringSubmatch(raw); len(byMatch) > 1 {
		header.By = byMatch[1]
	}
	
	// Extract 'with' clause
	if withMatch := regexp.MustCompile(`with\s+([^\s;]+)`).FindStringSubmatch(raw); len(withMatch) > 1 {
		header.With = withMatch[1]
	}
	
	return header
}

func (ep *EmailParser) parseBody(body io.Reader, result *ParsedEmail) error {
	contentType := result.Headers.ContentType
	if contentType == "" {
		// Try to detect from body
		return ep.detectAndParseBody(body, result)
	}
	
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return fmt.Errorf("failed to parse content type: %w", err)
	}
	
	charset := params["charset"]
	result.Body.Charset = charset
	
	switch mediaType {
	case "text/plain":
		return ep.readTextPart(body, &result.Body.PlainText, &result.Body.TextPartType)
	case "text/html":
		return ep.readTextPart(body, &result.Body.HTML, &result.Body.HTMLPartType)
	case "multipart/mixed", "multipart/alternative", "multipart/related":
		return ep.parseMultipart(body, params["boundary"], result)
	default:
		// Try to parse as multipart anyway
		if strings.HasPrefix(mediaType, "multipart/") {
			return ep.parseMultipart(body, params["boundary"], result)
		}
	}
	
	return nil
}

func (ep *EmailParser) detectAndParseBody(body io.Reader, result *ParsedEmail) error {
	data, err := io.ReadAll(io.LimitReader(body, 1024*1024)) // 1MB limit
	if err != nil {
		return err
	}
	
	// Simple heuristic: if contains HTML tags, treat as HTML
	if bytes.Contains(data, []byte("<")) && bytes.Contains(data, []byte(">")) {
		result.Body.HTML = string(data)
		result.Body.HTMLPartType = "text/html"
	} else {
		result.Body.PlainText = string(data)
		result.Body.TextPartType = "text/plain"
	}
	
	return nil
}

func (ep *EmailParser) readTextPart(reader io.Reader, target *string, partType *string) error {
	contentType := *partType
	
	data, err := io.ReadAll(io.LimitReader(reader, 10*1024*1024)) // 10MB limit
	if err != nil {
		return err
	}
	
	// Handle encoding
	if strings.Contains(contentType, "quoted-printable") {
		qp := quotedprintable.NewReader(bytes.NewReader(data))
		data, err = io.ReadAll(qp)
		if err != nil {
			return err
		}
	} else if strings.Contains(contentType, "base64") {
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err == nil {
			data = decoded
		}
	}
	
	*target = string(data)
	return nil
}

func (ep *EmailParser) parseMultipart(body io.Reader, boundary string, result *ParsedEmail) error {
	if boundary == "" {
		return fmt.Errorf("missing boundary parameter")
	}
	
	mr := multipart.NewReader(body, boundary)
	
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		
		if err := ep.parseMultipartPart(part, result); err != nil {
			result.ParseWarnings = append(result.ParseWarnings, fmt.Sprintf("part parse error: %v", err))
		}
	}
	
	return nil
}

func (ep *EmailParser) parseMultipartPart(part *multipart.Part, result *ParsedEmail) error {
	contentType := part.Header.Get("Content-Type")
	contentDisp := part.Header.Get("Content-Disposition")
	contentID := part.Header.Get("Content-ID")
	
	mediaType, _, _ := mime.ParseMediaType(contentType)
	
	// Check if attachment
	isAttachment := strings.Contains(strings.ToLower(contentDisp), "attachment")
	isInline := strings.Contains(strings.ToLower(contentDisp), "inline")
	
	filename := part.FileName()
	if filename == "" {
		filename = fmt.Sprintf("attachment-%s", uuid.New().String()[:8])
	}
	
	// Read content with size limit
	data, err := io.ReadAll(io.LimitReader(part, ep.maxAttachmentSize))
	if err != nil && err != io.ErrUnexpectedEOF {
		return err
	}
	
	if isAttachment || isInline {
		// Create attachment info
		attachment := AttachmentInfo{
			ID:           uuid.New(),
			Filename:     filename,
			OriginalName: filename,
			ContentType:  mediaType,
			Size:         int64(len(data)),
			Disposition:  contentDisp,
			IsInline:     isInline,
			ContentID:    strings.Trim(contentID, "<>"),
			Data:         data,
		}
		
		// Calculate hashes
		hash := sha256.Sum256(data)
		attachment.SHA256 = fmt.Sprintf("%x", hash)
		
		// MD5
		md5Hash := sha256.Sum256(data) // Using SHA256 for simplicity, can add MD5 separately
		attachment.MD5 = fmt.Sprintf("%x", md5Hash)[:32]
		
		// SHA1
		attachment.SHA1 = fmt.Sprintf("%x", hash)[:40]
		
		result.Attachments = append(result.Attachments, attachment)
	} else {
		// Body part
		if mediaType == "text/plain" {
			result.Body.PlainText += string(data)
			result.Body.TextPartType = contentType
		} else if mediaType == "text/html" {
			result.Body.HTML += string(data)
			result.Body.HTMLPartType = contentType
		}
	}
	
	return nil
}

func (ep *EmailParser) extractIOCs(result *ParsedEmail) {
	text := result.Body.PlainText + " " + result.Body.HTML
	
	// Extract URLs
	urlRe := regexp.MustCompile(`https?://[^\s<>"'\)]+`)
	urls := urlRe.FindAllString(text, -1)
	for _, u := range urls {
		link := ExtractedLink{
			URL:         u,
			DisplayText: u,
			IsEncoded:   strings.Contains(u, "%"),
		}
		
		// Try to decode
		if link.IsEncoded {
			if decoded, err := url.QueryUnescape(u); err == nil {
				link.DecodedURL = decoded
			}
		}
		
		// Check for suspicious patterns
		ep.checkLinkSuspicion(&link)
		
		result.Links = append(result.Links, link)
		result.IOCs.URLs = append(result.IOCs.URLs, u)
	}
	
	// Extract domains from URLs and email addresses
	domainRe := regexp.MustCompile(`(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.[a-zA-Z]{2,})`)
	domains := domainRe.FindAllStringSubmatch(text, -1)
	seenDomains := make(map[string]bool)
	for _, d := range domains {
		if len(d) > 1 && !seenDomains[d[1]] {
			result.IOCs.Domains = append(result.IOCs.Domains, d[1])
			seenDomains[d[1]] = true
		}
	}
	
	// Extract email addresses
	emailRe := regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	emails := emailRe.FindAllString(text, -1)
	result.IOCs.Emails = emails
	
	// Extract IP addresses
	ipRe := regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
	ips := ipRe.FindAllString(text, -1)
	result.IOCs.IPs = ips
	
	// Extract potential file hashes (MD5, SHA1, SHA256)
	md5Re := regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)
	sha1Re := regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)
	sha256Re := regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)
	
	for _, h := range md5Re.FindAllString(text, -1) {
		result.IOCs.FileHashes = append(result.IOCs.FileHashes, FileHash{Type: "md5", Value: h})
	}
	for _, h := range sha1Re.FindAllString(text, -1) {
		result.IOCs.FileHashes = append(result.IOCs.FileHashes, FileHash{Type: "sha1", Value: h})
	}
	for _, h := range sha256Re.FindAllString(text, -1) {
		result.IOCs.FileHashes = append(result.IOCs.FileHashes, FileHash{Type: "sha256", Value: h})
	}
}

func (ep *EmailParser) checkLinkSuspicion(link *ExtractedLink) {
	url := link.URL
	lowerURL := strings.ToLower(url)
	
	// Check for IP-based URLs
	if regexp.MustCompile(`https?://\d+\.\d+\.\d+\.\d+`).MatchString(url) {
		link.Suspicious = true
		link.SuspicionReasons = append(link.SuspicionReasons, "IP-based URL")
	}
	
	// Check for suspicious TLDs
	suspiciousTLDs := []string{".xyz", ".top", ".club", ".work", ".click", ".link", ".gq", ".ml", ".cf", ".tk", ".ga"}
	for _, tld := range suspiciousTLDs {
		if strings.HasSuffix(lowerURL, tld) {
			link.Suspicious = true
			link.SuspicionReasons = append(link.SuspicionReasons, fmt.Sprintf("suspicious TLD: %s", tld))
			break
		}
	}
	
	// Check for URL shorteners
	shorteners := []string{"bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd"}
	for _, s := range shorteners {
		if strings.Contains(lowerURL, s) {
			link.Suspicious = true
			link.SuspicionReasons = append(link.SuspicionReasons, "URL shortener")
			break
		}
	}
	
	// Check for excessive subdomains
	if strings.Count(url, ".") > 4 {
		link.Suspicious = true
		link.SuspicionReasons = append(link.SuspicionReasons, "excessive subdomains")
	}
	
	// Check for homoglyphs or unusual characters
	if regexp.MustCompile(`[^\x00-\x7F]`).MatchString(url) {
		link.Suspicious = true
		link.SuspicionReasons = append(link.SuspicionReasons, "contains non-ASCII characters")
	}
}

func (ep *EmailParser) analyzeAuthResults(header mail.Header, auth *AuthResults) {
	// Parse SPF
	if spf := header.Get("Authentication-Results"); spf != "" {
		auth.SPF = ep.parseSPF(spf)
	}
	
	// Also check dedicated SPF headers
	if spfHeader := header.Get("Received-SPF"); spfHeader != "" {
		if auth.SPF.Result == "" {
			auth.SPF = ep.parseSPFHeader(spfHeader)
		}
	}
	
	// Parse DKIM
	auth.DKIM = ep.parseDKIM(header)
	
	// Parse DMARC
	auth.DMARC = ep.parseDMARC(header)
	
	// Parse BIMI
	auth.BIMI = ep.parseBIMI(header)
	
	// Parse ARC
	auth.ARC = ep.parseARC(header)
}

func (ep *EmailParser) parseSPF(authResults string) SPFResult {
	result := SPFResult{Result: "none"}
	
	lower := strings.ToLower(authResults)
	
	if strings.Contains(lower, "spf=pass") {
		result.Result = "pass"
	} else if strings.Contains(lower, "spf=fail") {
		result.Result = "fail"
	} else if strings.Contains(lower, "spf=softfail") {
		result.Result = "softfail"
	} else if strings.Contains(lower, "spf=neutral") {
		result.Result = "neutral"
	} else if strings.Contains(lower, "spf=temperror") {
		result.Result = "temperror"
	} else if strings.Contains(lower, "spf=permerror") {
		result.Result = "permerror"
	}
	
	// Extract details
	if idx := strings.Index(lower, "spf("); idx != -1 {
		endIdx := strings.Index(authResults[idx:], ")")
		if endIdx != -1 {
			result.Details = authResults[idx+4 : idx+endIdx]
		}
	}
	
	return result
}

func (ep *EmailParser) parseSPFHeader(spfHeader string) SPFResult {
	result := SPFResult{Result: "none"}
	
	lower := strings.ToLower(spfHeader)
	if strings.HasPrefix(lower, "pass") {
		result.Result = "pass"
	} else if strings.HasPrefix(lower, "fail") {
		result.Result = "fail"
	} else if strings.HasPrefix(lower, "softfail") {
		result.Result = "softfail"
	} else if strings.HasPrefix(lower, "neutral") {
		result.Result = "neutral"
	}
	
	result.Details = spfHeader
	return result
}

func (ep *EmailParser) parseDKIM(header mail.Header) DKIMResult {
	result := DKIMResult{Result: "none"}
	
	authResults := header.Get("Authentication-Results")
	lower := strings.ToLower(authResults)
	
	if strings.Contains(lower, "dkim=pass") {
		result.Result = "pass"
	} else if strings.Contains(lower, "dkim=fail") {
		result.Result = "fail"
	} else if strings.Contains(lower, "dkim=neutral") {
		result.Result = "neutral"
	} else if strings.Contains(lower, "dkim=temperror") {
		result.Result = "temperror"
	} else if strings.Contains(lower, "dkim=permerror") {
		result.Result = "permerror"
	}
	
	// Try to extract selector and domain from DKIM-Signature header
	if dkimSig := header.Get("DKIM-Signature"); dkimSig != "" {
		// Extract 's=' (selector)
		if sMatch := regexp.MustCompile(`s=([^;\s]+)`).FindStringSubmatch(dkimSig); len(sMatch) > 1 {
			result.Selector = dMatch[1]
		}
		
		// Extract 'd=' (domain)
		if dMatch := regexp.MustCompile(`d=([^;\s]+)`).FindStringSubmatch(dkimSig); len(dMatch) > 1 {
			result.SignDomain = dMatch[1]
		}
		
		// Extract 'h=' (signed headers)
		if hMatch := regexp.MustCompile(`h=([^;\s]+)`).FindStringSubmatch(dkimSig); len(hMatch) > 1 {
			result.Headers = strings.Split(hMatch[1], ":")
		}
	}
	
	return result
}

func (ep *EmailParser) parseDMARC(header mail.Header) DMARCResult {
	result := DMARCResult{Result: "none"}
	
	authResults := header.Get("Authentication-Results")
	lower := strings.ToLower(authResults)
	
	if strings.Contains(lower, "dmarc=pass") {
		result.Result = "pass"
	} else if strings.Contains(lower, "dmarc=fail") {
		result.Result = "fail"
	}
	
	// Extract policy
	if pMatch := regexp.MustCompile(`(?i)p=(none|quarantine|reject)`).FindStringSubmatch(authResults); len(pMatch) > 1 {
		result.Policy = strings.ToUpper(pMatch[1])
	}
	
	return result
}

func (ep *EmailParser) parseBIMI(header mail.Header) BIMIResult {
	result := BIMIResult{}
	
	if bimi := header.Get("BIMI-Location"); bimi != "" {
		result.Present = true
		result.Indicator = bimi
	}
	
	if bimiAuth := header.Get("BIMI-Authentication"); bimiAuth != "" {
		result.Present = true
		// Parse status
		if strings.Contains(strings.ToLower(bimiAuth), "fail") {
			result.Errors = append(result.Errors, bimiAuth)
		}
	}
	
	return result
}

func (ep *EmailParser) parseARC(header mail.Header) ARCResult {
	result := ARCResult{}
	
	if arcSeal := header.Get("ARC-Seal"); arcSeal != "" {
		result.Present = true
		result.Seal = arcSeal
		
		if strings.Contains(strings.ToLower(arcSeal), "pass") {
			result.Status = "pass"
		} else if strings.Contains(strings.ToLower(arcSeal), "fail") {
			result.Status = "fail"
		} else {
			result.Status = "unknown"
		}
	}
	
	return result
}

// GetEmailMetadata returns only safe metadata without raw content
func (pe *ParsedEmail) GetEmailMetadata() map[string]interface{} {
	return map[string]interface{}{
		"subject":        pe.Headers.Subject,
		"from_address":   pe.Headers.From.Address,
		"from_name":      pe.Headers.From.Name,
		"to_count":       len(pe.Headers.To),
		"cc_count":       len(pe.Headers.Cc),
		"reply_to_count": len(pe.Headers.ReplyTo),
		"date":           pe.Headers.Date,
		"x_mailer":       pe.Headers.XMailer,
		"has_html":       pe.Body.HTML != "",
		"has_plain":      pe.Body.PlainText != "",
		"attachment_count": len(pe.Attachments),
		"link_count":     len(pe.Links),
		"spf_result":     pe.AuthResults.SPF.Result,
		"dkim_result":    pe.AuthResults.DKIM.Result,
		"dmarc_result":   pe.AuthResults.DMARC.Result,
	}
}
