# PhishGuard - Privacy-Aware Phishing Investigation Platform

## Executive Summary

PhishGuard is a production-grade, secure-by-design AI-assisted phishing analysis system designed for MSSP environments. The platform prioritizes data privacy by ensuring ALL sensitive processing happens locally, while leveraging AI for analyst augmentation.

## Core Security Principles

### LOCAL-FIRST SECURITY MODEL

**NEVER Sent Externally:**
- Raw EML files
- Raw attachments  
- Internal domains
- Usernames
- Internal email threads
- Sensitive URLs
- Customer identifiers
- Raw logs

**ALWAYS Processed Locally:**
- EML parsing
- Attachment extraction
- OCR processing
- URL extraction
- SPF/DKIM/DMARC validation
- Attachment hashing (MD5, SHA1, SHA256)
- HTML rendering
- Brand abuse detection
- Domain similarity analysis
- YARA scanning
- IOC extraction
- CyberChef-like decoding

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     FRONTEND (Next.js + Tailwind)                │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────┐ │
│  │ Email Upload│ │IOC Dashboard│ │Campaign View│ │Workbench  │ │
│  └─────────────┘ └─────────────┘ └─────────────┘ └───────────┘ │
└─────────────────────────────────────────────────────────────────┘
                              │ HTTPS
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                  BACKEND (Golang + Fiber)                        │
│                                                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    PRIVACY GATEWAY                         │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐ │  │
│  │  │Sensitive │ │ Masking  │ │Tokenizing│ │ Prompt       │ │  │
│  │  │Detection │ │ Engine   │ │ Service  │ │ Sanitization │ │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────┘ │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                   │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │ EML Parser   │ │ IOC Extractor│ │ AI Orchestr. │             │
│  │ (Local Only) │ │ & Enricher   │ │ (LiteLLM)    │             │
│  └──────────────┘ └──────────────┘ └──────────────┘             │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐             │
│  │ Brand Abuse  │ │ CyberChef    │ │ Threat Intel │             │
│  │ Detector     │ │ Decoders     │ │ Connector    │             │
│  └──────────────┘ └──────────────┘ └──────────────┘             │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│   SQLite3     │    │    Redis      │    │    Qdrant     │
│ (Investigation│    │  (Cache/      │    │ (Vector Store │
│   Data)       │    │   Sessions)   │    │  Embeddings)  │
└───────────────┘    └───────────────┘    └───────────────┘
        │
        ▼
┌───────────────┐
│    NATS       │
│ (Event Bus)   │
└───────────────┘
        │
    ┌───┴───┐
    ▼       ▼
┌───────┐ ┌───────┐
│Python │ │External│
│Workers│ │APIs    │
│(OCR,  │ │(VT,   │
│YARA)  │ │URLScan)│
└───────┘ └───────┘
```

## Technology Stack

### Backend
- **Golang** - Type-safe, performant backend
- **Fiber** - High-performance web framework
- **SQLite3** - Local investigation storage
- **Redis** - Session management and caching
- **NATS** - Event-driven messaging

### Frontend
- **Next.js** - React framework
- **Tailwind CSS** - Utility-first styling

### AI Integration
- **LiteLLM** - Unified LLM interface
- **DeepSeek API** - External AI (sanitized data only)
- **Claude API** - External AI (sanitized data only)
- **Ollama** - Local models for sensitive tasks

### Vector Database
- **Qdrant** - Semantic search for campaign correlation

### Python Workers
- **mail-parser** - Safe EML processing
- **Tesseract OCR** - Image text extraction
- Custom CyberChef-like decoders

## Privacy Gateway Implementation

### Sensitive Data Detection
- Regex-based pattern matching
- NER (Named Entity Recognition) masking
- Custom dictionaries for internal systems
- Semantic sensitivity scoring (1-10)

### Masking Types
| Type | Sensitivity | Example Token |
|------|-------------|---------------|
| Credentials | 10 | `[[credential_a8f3d2]]` |
| JWT Tokens | 9 | `[[jwt_b7e4c1]]` |
| Internal Systems | 8 | `[[internal_system_c9]]` |
| Usernames | 7 | `[[username_d4e5f6]]` |
| Emails | 6 | `[[email_e8f9a0]]` |
| Ticket IDs | 5 | `[[ticket_id_f1g2h3]]` |
| URLs | 5 | `[[url_g4h5i6]]` |
| Domains | 4 | `[[domain_h7i8j9]]` |
| IPs | 3 | `[[ip_i0j1k2]]` |

### Reversible Tokenization
- Secure local mapping storage
- AES-GCM encryption for mappings
- Automatic detokenization for analyst view

## Prompt Injection Protection

### Removed Elements
1. **Hidden HTML** - `<script>`, `<iframe>`, event handlers
2. **Comments** - `<!-- ... -->`
3. **Invisible Unicode** - Zero-width chars, BOM
4. **Markdown Injections** - Headers, lists in content
5. **AI Instructions** - "Ignore previous instructions"

### Validation Pipeline
```
Raw Input → HTML Strip → Unicode Clean → 
Pattern Detect → Risk Score → Allow/Block
```

## AI Workflow

### Structured Input (NEVER Raw EML)
```json
{
  "spf": "fail",
  "dkim": "none", 
  "dmarc": "fail",
  "reply_to_mismatch": true,
  "urgency_score": 91,
  "credential_harvest": true,
  "brand_impersonation": "Microsoft",
  "sandbox_verdict": "suspicious",
  "detected_ttps": ["T1566.002"],
  "attachment_count": 1,
  "url_count": 3
}
```

### AI Analysis Output
```json
{
  "verdict": "phishing",
  "confidence_score": 94,
  "explanation": "...",
  "attack_chain": "...",
  "objectives": ["Credential theft", "Session hijacking"],
  "risk_level": "high",
  "recommended_actions": ["Block domain", "Reset credentials"],
  "mitre_attack": ["T1566.002", "T1598.003"],
  "d3fend": ["D3-DA", "D3-ME"],
  "reasoning": "..."
}
```

## IOC Pipeline

### Extraction
- Domains from URLs and email addresses
- IP addresses from headers and links
- URLs from body and redirects
- File hashes (MD5, SHA1, SHA256)
- Sender infrastructure

### Processing
1. **Normalization** - Lowercase, remove www
2. **Deduplication** - Cross-investigation
3. **Enrichment** - VT, URLScan, ThreatFox, AbuseIPDB
4. **Scoring** - Weighted threat score
5. **Correlation** - Campaign linking

### Enrichment Sources
- VirusTotal
- URLScan.io
- ThreatFox
- AbuseIPDB
- WHOIS
- Passive DNS

## Phishing Detection Features

### Authentication Analysis
- SPF validation
- DKIM signature verification
- DMARC policy enforcement

### Brand Impersonation
- Homoglyph detection (а vs a)
- Levenshtein similarity
- Punycode analysis
- Favicon hash matching
- Logo similarity

### Behavioral Indicators
- Urgency scoring (keywords)
- Credential harvesting patterns
- Login form detection
- Threat language analysis

## CyberChef-like Decoding

### Supported Decoders
- Base64 / Base64URL
- XOR with key detection
- URL encoding/decoding
- PowerShell deobfuscation
- Gzip/Zlib decompression
- Hex decoding
- ROT13/Caesar cipher

### AI Explanation
Decoded payloads are explained by AI:
- Command purpose
- Malicious indicators
- MITRE ATT&CK mapping

## Analyst Output

### Investigation Report
1. **Verdict** - phishing/spam/malware/benign
2. **Confidence Score** - 0-100
3. **IOC Summary** - All extracted indicators
4. **Attack Chain** - Step-by-step explanation
5. **MITRE ATT&CK** - Technique mapping
6. **D3FEND** - Countermeasure recommendations
7. **Remediation** - Actionable steps
8. **User Guidance** - Notification templates

### Response Recommendations

**If Spam:**
- Block sender address
- Add to spam rules
- Notify users if widespread

**If Phishing:**
- Reset affected credentials
- Invalidate sessions
- Hunt for similar emails
- Check mailbox rules
- Block domains/IPs
- Search IOC across tenants

**If Malware Delivery:**
- Isolate affected hosts
- Scan endpoints for hashes
- Block C2 infrastructure
- Investigate persistence
- Sweep network for IOCs

## Testing Strategy

### Safe Test Sources
- PhishTank public samples
- MalwareBazaar
- URLHaus
- ANY.RUN public samples
- OpenPhish

### Testing Environment
- Isolated VM network
- Docker sandbox containers
- No-network analysis mode
- Browser isolation for URLs

## Code Quality Requirements

### Mandatory Practices
- Secure coding standards
- Peer code review
- Dependency vulnerability scanning
- Threat modeling per feature
- Unit tests (>80% coverage)
- Integration tests
- Structured logging
- Retry logic with backoff
- Observability (metrics, traces)
- Comprehensive error handling

### Security Reviews
- Prompt injection testing
- SSRF vulnerability review
- Sandbox escape analysis
- RAG poisoning prevention
- Data leakage audits

## Deployment Considerations

### Infrastructure
- Air-gapped option for sensitive clients
- On-premises deployment support
- Multi-tenant isolation
- Encrypted data at rest
- TLS everywhere

### Compliance
- GDPR data handling
- SOC2 controls
- ISO 27001 alignment
- Audit logging
- Data retention policies

## Philosophy

This platform is NOT:
- A generic AI chatbot
- A raw EML summarizer  
- An autonomous AI SOC

This platform IS:
- A privacy-aware phishing investigation platform
- An analyst augmentation system
- A structured investigation workflow engine
- A secure MSSP-grade phishing intelligence platform

Human analysts remain in control. AI provides augmentation, not automation.
