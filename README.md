# Privacy-Aware Phishing Investigation Platform

A production-grade, secure-by-design AI-assisted phishing analysis system for MSSP environments.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FRONTEND (Next.js)                                │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐   │
│  │ Email Upload│ │IOC Dashboard│ │Campaign View│ │ Analyst Workbench   │   │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      BACKEND (Golang + Fiber)                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        PRIVACY GATEWAY                                │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────────────┐ │   │
│  │  │Sensitive │ │ Masking  │ │Tokenizing│ │ Prompt Sanitization      │ │   │
│  │  │Detection │ │ Engine   │ │ Service  │ │ & Injection Protection   │ │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────────────────────┘ │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ EML Parser   │  │ IOC Extractor│  │ AI Orchestr. │  │ Sandbox Mgr  │     │
│  │ (Local Only) │  │ & Enricher   │  │ (LiteLLM)    │  │ (Docker)     │     │
│  └──────────────┘  └──────────────┘ └──────────────┘ └──────────────┘     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Brand Abuse  │  │ CyberChef    │  │ Threat Intel │  │ Campaign     │     │
│  │ Detector     │  │ Decoders     │  │ Connector    │  │ Analyzer     │     │
│  └──────────────┘  └──────────────┘ └──────────────┘ └──────────────┘     │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
            ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
            │   SQLite3     │ │    Redis      │ │    Qdrant     │
            │ (Investigation│ │  (Cache/      │ │ (Vector Store │
            │   Data)       │ │   Sessions)   │ │  Embeddings)  │
            └───────────────┘ └───────────────┘ └───────────────┘
                    │
                    ▼
            ┌───────────────┐
            │    NATS       │
            │ (Event Bus)   │
            └───────────────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
┌───────────────┐       ┌───────────────┐
│ Python Workers│       │ External APIs │
│ (mail-parser, │       │ (VirusTotal,  │
│  Tesseract,   │       │  URLScan,     │
│  OCR, YARA)   │       │  ThreatFox)   │
└───────────────┘       └───────────────┘
```

## Security Model: LOCAL-FIRST

### NEVER Sent Externally
- Raw EML files
- Raw attachments
- Internal domains
- Usernames
- Internal email threads
- Sensitive URLs
- Customer identifiers
- Raw logs

### ALWAYS Processed Locally
- EML parsing
- Attachment extraction
- OCR processing
- URL extraction
- SPF/DKIM/DMARC validation
- Attachment hashing
- HTML rendering
- Brand abuse detection
- Domain similarity analysis
- YARA scanning
- IOC extraction
- CyberChef decoding

## Components

### Backend (Golang)
- **Fiber** - High-performance web framework
- **SQLite3** - Local investigation storage
- **Redis** - Session management and caching
- **NATS** - Event-driven architecture

### Frontend (Next.js)
- **Tailwind CSS** - Utility-first styling
- Real-time investigation dashboards
- Analyst workbench interface

### AI Integration
- **LiteLLM** - Unified LLM interface
- **DeepSeek API** - External AI (sanitized data only)
- **Claude API** - External AI (sanitized data only)
- **Ollama** - Local models for sensitive tasks

### Vector Database
- **Qdrant** - Semantic search for campaigns

### Python Workers
- **mail-parser** - Safe EML processing
- **Tesseract OCR** - Image text extraction
- Custom CyberChef-like decoders

### Sandbox
- Docker isolated containers for attachment analysis

## Privacy Gateway

Before any external AI request:
1. Detect sensitive data (regex + NER)
2. Mask sensitive identifiers
3. Tokenize with reversible mapping
4. Sanitize prompts
5. Classify sensitivity level
6. Enforce approval workflows

## Prompt Injection Protection

All inputs are sanitized to remove:
- Hidden HTML elements
- Comments
- Invisible Unicode characters
- Markdown injections
- Embedded AI instructions

## MITRE ATT&CK Coverage

- T1566.002 - Spearphishing Link
- T1566.001 - Spearphishing Attachment
- T1598.003 - Spearphishing via Service
- T1534 - Internal Spearphishing

## Getting Started

```bash
# Start infrastructure
docker-compose up -d

# Initialize database
./backend/phishguard migrate

# Start backend
cd backend && go run cmd/main.go

# Start frontend
cd frontend && npm run dev
```

## License

Proprietary - MSSP Use Only
