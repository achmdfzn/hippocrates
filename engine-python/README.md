# Hippocrates ML Detection Engine

Python sidecar service for deep ML-driven threat detection, complementing the TypeScript Hippocrates library.

## Overview

The ML Engine extends the TypeScript library's built-in L1-L6 analyzers with advanced detection:

| Analyzer | What It Detects | Methods |
|----------|----------------|---------|
| **Prompt Injection** | Prompt override, jailbreak, DAN, system prompt hijack | Heuristic patterns, entropy analysis, structural checks |
| **Advanced Obfuscation** | Base64, hex, Unicode, URL encoding, transform chaining | Extended regex, character frequency, Shannon entropy |
| **Content Risk** | SQLi, XSS, path traversal, command injection, SSRF | Multi-category pattern matching, recursive scanning |

## Architecture

```
┌─────────────────────┐     POST /analyze     ┌──────────────────────┐
│  TypeScript Library  │ ──────────────────►   │  Python ML Engine    │
│  (withHippocrates)   │                      │  (FastAPI + asyncio) │
│                      │ ◄──────────────────  │                      │
│  mlEnginePlugin      │    { score, tags,    │  prompt_injection    │
│  (src/plugins/)      │      analyses }      │  obfuscation_advanced│
│                      │                      │  content_risk        │
└─────────────────────┘                      └──────────────────────┘
```

## Quick Start

```bash
# Install dependencies
cd engine-python
pip install -r requirements.txt

# Run locally
python -m app.main

# Health check
curl http://localhost:8000/health

# Analyze a request
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "test-1",
    "ip": "1.2.3.4",
    "method": "POST",
    "path": "/api/data",
    "headers": {"content-type": "application/json"},
    "body": {"query": "1'\'' OR '\''1'\''='\''1"}
  }'
```

## Docker

```bash
docker compose up --build
```

This starts both the ML engine (port 8000) and Redis (port 6379).

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `HIPPO_ML_HOST` | `0.0.0.0` | Bind address |
| `HIPPO_ML_PORT` | `8000` | HTTP port |
| `HIPPO_ML_LOG_LEVEL` | `info` | Logging level |
| `HIPPO_ML_ENABLE_PROMPT_INJECTION` | `true` | Enable prompt injection analyzer |
| `HIPPO_ML_ENABLE_OBFUSCATION_ADVANCED` | `true` | Enable obfuscation analyzer |
| `HIPPO_ML_ENABLE_CONTENT_RISK` | `true` | Enable content risk analyzer |
| `HIPPO_ML_PROMPT_INJECTION_WEIGHT` | `60` | Score weight |
| `HIPPO_ML_OBFUSCATION_ADVANCED_WEIGHT` | `70` | Score weight |
| `HIPPO_ML_CONTENT_RISK_WEIGHT` | `30` | Score weight |
| `HIPPO_ML_MAX_BODY_BYTES` | `1048576` | Max body size (1MB) |
| `HIPPO_ML_REQUEST_TIMEOUT_SECONDS` | `5` | Analyzer timeout |

## API

### `POST /analyze`

**Request:**
```json
{
  "request_id": "correlation-id",
  "ip": "1.2.3.4",
  "method": "POST",
  "path": "/api/data",
  "headers": {
    "content-type": "application/json"
  },
  "body": { ... },
  "body_raw": "..." 
}
```

**Response:**
```json
{
  "score": 0,
  "tags": [],
  "analyses": {
    "prompt_injection": { "score": 0, "tags": [], "confidence": 0.0 },
    "obfuscation_advanced": { "score": 0, "tags": [], "confidence": 0.0 },
    "content_risk": { "score": 0, "tags": [], "confidence": 0.0 }
  }
}
```

### `GET /health`

```json
{
  "status": "ok",
  "analyzers": {
    "prompt_injection": true,
    "obfuscation_advanced": true,
    "content_risk": true
  }
}
```

## Tests

```bash
cd engine-python
pip install -r requirements.txt
pytest -v
```
