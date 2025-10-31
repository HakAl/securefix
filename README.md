# SecureFix

![Security Scan](https://github.com/HakAl/securefix/actions/workflows/securefix.yml/badge.svg)
![Tests](https://github.com/HakAl/securefix/actions/workflows/test.yml/badge.svg)

A static Python application security testing (SAST) suite with intelligent remediation powered by retrieval-augmented generation (RAG).
SecureFix combines deterministic vulnerability detection with context-aware fix suggestions to help developers identify and resolve security issues efficiently.

## Overview

SecureFix bridges rule-based precision and AI-driven guidance through two core capabilities:

- **Static Analysis Engine**: Deterministic detection of SQL injection, hardcoded secrets, XSS, CVE databases, and many more thanks to Bandit!
- **Smart Remediation**: RAG-powered fix generation that retrieves relevant security patterns and synthesizes contextual remediation guidance

## Features

### Detection Capabilities

- **Code-level vulnerabilities** via Bandit analysis
  - SQL injection through unsafe query construction
  - Hardcoded secrets (API keys, tokens, credentials)
  - See: sast/bandit_mapper.py for full list
- **Dependency vulnerabilities** via CVE scanning
  - Real-time lookup via OSV database API

### Remediation Capabilities

- **Semantic retrieval** of relevant security patterns using hybrid BM25 + vector search
- **Context-aware fix generation** with explanations and confidence scoring
- **Multi-LLM support** for both local (Ollama) and cloud-based (Google Gen AI) processing
- **Query caching** for performance optimization

### Performance Benchmarks

- Success rate: 100% (llama3.2:3b on 34 diverse vulnerabilities)
- Confidence: 97% High confidence (33/34)
- Speed: ~23s per vulnerability (local inference)
- Corpus: 14,348 chunks, hybrid BM25 + vector search

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/hakal/securefix.git
cd securefix

# Install with pip (recommended)
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"

# Or install with all optional dependencies
pip install -e ".[all]"
```

### Optional Dependencies

```bash
# Install with LlamaCPP support (for local model inference)
pip install -e ".[llamacpp]"

# Install development tools (pytest, coverage)
pip install -e ".[dev]"
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# For Google Gemini support
GOOGLE_API_KEY=your_api_key_here

# Optional: Default model configuration
MODEL_NAME=llama3.2:3b

# With environment variables
LLAMACPP_MODEL_PATH=./models/qwen2.5-3b-instruct-q4_k_m.gguf
LLAMACPP_N_CTX=2048
LLAMACPP_N_THREADS=14
LLAMACPP_N_GPU_LAYERS=1
LLAMACPP_N_BATCH=512
```

### LLM Setup

**Ollama (Local - Default):**
- Install Ollama: https://ollama.com/
- Pull a model: `ollama pull llama3.2:3b`
- No API key required

**Google Gemini (Cloud):**
- Set `GOOGLE_API_KEY` in `.env`
- Use `--llm-mode google` flag
- Requires internet connection

**Model Recommendations**

**For best results:**
- Google Gemini (recommended, 100% success rate)
- llama3.2:3b or larger (100% success rate)

**Not recommended:**
- Models < 3B parameters (phi3:mini, deepseek-coder:1.3b) - inconsistent output quality
- deepseek-coder:1.3b is fastest. Provides accurate results, supporting docs, but no suggested fixes.

**Local Mode (Ollama)**:
```bash
# Install Ollama from ollama.com
ollama pull llama3.2:3b
# LlamaCPP (alternative local option)
# Install with: pip install securefix[llamacpp]
```

**Cloud Mode (Google Gen AI)**:
```bash
# Get API key from Google AI Studio
echo "GOOGLE_API_KEY=your_key_here" > .env
```

## Usage

### Build Knowledge Base (One-time setup)

First, ingest your security corpus to build the vector database:

```bash
# Download security corpus (use this script, or source your own)
python securefix/corpus_downloader.py --corpus-path ./remediation/corpus

# Build vector database from corpus
securefix ingest

# Or specify custom corpus path
securefix ingest --corpus-path /path/to/corpus

# Rebuild existing database
securefix ingest --rebuild
```

**Supported corpus formats:**
- `.csv` - CWE weakness data
- `.md` - OWASP cheat sheets
- `.yaml`/`.yml` - PyPA security advisories

### Basic Scanning

```bash
# Scan a single file
securefix scan path/to/code.py

# Scan a directory
securefix scan src/

# Scan with dependencies
securefix scan src/ --dependencies requirements.txt

# Custom output file
securefix scan src/ -d requirements.txt -o my_report.json
```

### Remediation

```bash
# Generate fix suggestions
securefix fix report.json --output fixes.json

# Interactive mode (review and approve each fix)
securefix fix report.json --interactive

# Choose LLM backend
securefix fix report.json --llm-mode local    # Ollama (default)
securefix fix report.json --llm-mode google   # Google Gemini
securefix fix report.json --llm-mode llamacpp # LLamacpp
# With CLI option
securefix fix report.json --llm-mode llamacpp --model-path ./models/llama-3.2-3b.gguf

# Specify model name
securefix fix report.json --model-name llama3.2:3b

# Disable semantic caching
securefix fix report.json --no-cache

# Custom vector database location
securefix fix report.json --persist-dir ./my_chroma_db

# Filter by severity (only fix high/critical vulnerabilities)
securefix fix report.json --severity-filter high

# Only remediate SAST findings (skip CVE findings)
securefix fix report.json --sast-only

# Only remediate CVE findings (skip SAST findings)
securefix fix report.json --cve-only
```

### Docker

```bash
# Build
docker build -t securefix:latest .

# Or with compose
docker-compose build

# Scan
docker-compose run --rm securefix scan /scan --output /data/reports/report.json

# Fix (LlamaCPP)
docker-compose run --rm securefix fix /data/reports/report.json --llm-mode llamacpp --output /data/fixes/fixes.json
```

### Output Format

**Vulnerability Report**:
```json
{
  "summary": {
    "total_findings": 1,
    "total_cve_findings": 1,
    "by_severity": {
      "low": 0,
      "medium": 0,
      "high": 1,
      "critical": 0
    },
    "scan_timestamp": "2025-10-29T16:25:28.791091"
  },
  "sast_findings": [
    {
      "type": "Insecure Configuration",
      "line": 112,
      "severity": "high",
      "confidence": "medium",
      "snippet": "# Running with hardcoded credentials and debug mode\napp.run(debug=True, host='0.0.0.0', port=5000)",
      "description": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
      "file": "vulnerable\\admin_panel.py",
      "bandit_test_id": "B201"
    }
  ],
  "cve_findings": [
    {
      "package": "flask",
      "version": "0.12",
      "cves": [
        "GHSA-562c-5r94-xh97",
        "GHSA-5wv5-4vpf-pj6m",
        "GHSA-m2qf-hxjv-5gpq",
        "PYSEC-2018-66",
        "PYSEC-2019-179",
        "PYSEC-2023-62"
      ],
      "file": ".\\vulnerable\\requirements-vulnerable.txt"
    }
  ]
}
```

**Remediation Output**:
```json
{
  "summary": {
    "scan_timestamp": "2025-10-29T16:50:52.333427",
    "remediation_timestamp": "2025-10-29T16:53:07.027683",
    "llm_info": "Google gemini-2.0-flash-lite",
    "total_findings": 2,
    "sast_findings_count": 1,
    "cve_findings_count": 1,
    "successful_remediations": 2,
    "failed_remediations": 0,
    "by_severity": {
      "critical": 0,
      "high": 1,
      "medium": 1,
      "low": 0
    },
    "by_confidence": {
      "High": 2,
      "Medium": 0,
      "Low": 0
    }
  },
  "remediations": [
    {
      "finding": {
        "type": "Insecure Configuration",
        "line": 112,
        "severity": "high",
        "confidence": "medium",
        "snippet": "# Running with hardcoded credentials and debug mode\napp.run(debug=True, host='0.0.0.0', port=5000)",
        "description": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
        "file": "vulnerable\\admin_panel.py",
        "bandit_test_id": "B201"
      },
      "suggested_fix": "app.run(debug=False, host='0.0.0.0', port=5000)",
      "explanation": "The original code runs the application in debug mode with hardcoded credentials, making it vulnerable to exploitation by attackers who can easily access sensitive information and potentially gain unauthorized access.",
      "confidence": "High",
      "cwe_id": "A6:2017-Security Misconfiguration",
      "source_documents": [
        {
          "source": "remediation\\corpus\\cheatsheets\\Secure_Code_Review_Cheat_Sheet.md",
          "doc_type": "owasp_cheatsheet"
        },
        {
          "source": "remediation\\corpus\\cheatsheets\\Abuse_Case_Cheat_Sheet.md",
          "doc_type": "owasp_cheatsheet"
        }
      ]
    },
    {
      "finding": {
        "package": "flask",
        "version": "0.12",
        "cves": [
          "GHSA-562c-5r94-xh97",
          "GHSA-5wv5-4vpf-pj6m",
          "GHSA-m2qf-hxjv-5gpq",
          "PYSEC-2018-66",
          "PYSEC-2019-179",
          "PYSEC-2023-62"
        ],
        "file": ".\\vulnerable\\requirements-vulnerable.txt"
      },
      "suggested_fix": "flask>=2.0.0",
      "explanation": "The vulnerability lies in the use of an outdated version of Flask (0.12) which is known to have multiple security vulnerabilities. Upgrading to a more recent version, such as 2.0.0 or later, addresses these known vulnerabilities by incorporating security patches and improvements.",
      "confidence": "High",
      "cwe_id": null,
      "source_documents": [
        {
          "source": "./remediation/corpus\\1040.csv",
          "doc_type": "cwe"
        },
        {
          "source": "./remediation/corpus\\1430.csv",
          "doc_type": "cwe"
        }
      ]
    }
  ]
}
```


## Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# Run with coverage
pytest --cov=securefix --cov-report=html

# Run specific test categories
pytest -m unit          # Unit tests only
pytest -m integration   # Integration tests only
pytest -m "not slow"    # Skip slow tests
```

## Technical Approach

### Detection Pipeline

1. **Bandit**: Processes each file, builds an AST from it, and runs appropriate plugins against the AST nodes
4. **CVE Lookup**: Query local database and OSV API for known vulnerabilities

### Remediation Pipeline

1. **Retrieval**: Hybrid BM25 + semantic search over security pattern corpus
2. **Context Assembly**: Combine vulnerability details with retrieved patterns
3. **Generation**: LLM synthesizes fix with explanation and confidence score
4. **Caching**: Store results to optimize repeated vulnerability types

## Testing

```bash
# Run test suite
pytest -v

# Run with coverage
pytest --cov=securefix tests/
```

## Limitations

- Python-only support in current implementation
- Remediation suggestions are advisory, not guaranteed safe
- Local LLM mode requires sufficient RAM (8GB+ recommended)

## Future Work

- Multi-language support (JavaScript, Java, Go)
- Runtime Application Self-Protection (RASP) integration
- Machine learning for false positive reduction

## Dependencies

- langchain: RAG framework and LLM orchestration
- chromadb: Vector storage for security patterns
- sentence-transformers: Semantic embedding generation
- ollama: Local LLM support
- click: CLI framework

See `pyproject.toml` for complete dependency list

## References

- Bandit: https://github.com/PyCQA/bandit
- OWASP Cheat Sheets: https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets
- CWE Database: https://cwe.mitre.org/
- OSV Vulnerability Database: https://osv.dev/
- Python Package Advisory DB: https://github.com/pypa/advisory-database