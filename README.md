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

- **Code-level vulnerabilities** via Abstract Syntax Tree (AST) analysis
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

## Installation

```bash
git clone https://github.com/hakal/securefix.git
cd securefix
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### LLM Setup

**Local Mode (Ollama)**:
```bash
# Install Ollama from ollama.ai
ollama pull llama3.2:3b  # for speed, or for more accuracy llama3.1:8b 
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
# Use this script, or source your own
python corpus_downloader.py --corpus-path ./remediation/corpus

# Use default corpus location (./remediation/corpus)
python securefix.py ingest

# Or specify custom corpus path
python securefix.py ingest --corpus-path /path/to/corpus

# Rebuild existing database
python securefix.py ingest --rebuild
```

**Supported corpus formats:**
- `.csv` - CWE weakness data
- `.md` - OWASP cheat sheets
- `.yaml`/`.yml` - PyPA security advisories

### Basic Scanning

```bash
# Scan a single file
python securefix.py scan path/to/code.py

# Scan a directory
python securefix.py scan src/

# Scan with dependencies
python securefix.py scan src/ --dependencies requirements.txt

# Custom output file
python securefix.py scan src/ -d requirements.txt -o my_report.json
```

### Remediation

```bash
# Generate fix suggestions
python securefix.py fix report.json --output fixes.json

# Interactive mode
python securefix.py fix report.json --interactive

# Local or cloud
python securefix.py fix report.json --llm-mode local|google

# Choose model
python securefix.py fix report.json --model-name qwen3:4b

# Disable cache
python securefix.py fix report.json --no-cache

# Vector DB location
python securefix.py fix report.json --persist-dir /remediation/chroma_db

# Filter by severity
python securefix.py fix report.json --severity-filter
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
      "line": 95,
      "severity": "high",
      "confidence": "medium",
      "snippet": "app.secret_key = \"flask-insecure-secret-key-123456\"\napp.run(debug=True, host='0.0.0.0')",
      "description": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
      "file": "vulnerable\\vulnerable_app.py"
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
        "line": 95,
        "severity": "high",
        "confidence": "medium",
        "snippet": "app.secret_key = \"flask-insecure-secret-key-123456\"\napp.run(debug=True, host='0.0.0.0')",
        "description": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
        "file": "vulnerable\\vulnerable_app.py"
      },
      "suggested_fix": "import os\n\napp.secret_key = os.environ.get('FLASK_SECRET_KEY') or 'generate-a-strong-secret-key'\napp.run(debug=True, host='0.0.0.0')",
      "explanation": "The original code uses a hardcoded, insecure secret key, making the application vulnerable to attacks. The fix retrieves the secret key from an environment variable, which is a more secure practice. If the environment variable is not set, a placeholder is used, but it should be replaced with a strong, randomly generated secret key in a production environment.",
      "confidence": "High",
      "cwe_id": "CWE-453",
      "source_documents": [
        {
          "source": "./remediation/corpus\\888.csv",
          "doc_type": "cwe"
        },
        {
          "source": "./remediation/corpus\\700.csv",
          "doc_type": "cwe"
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

See `requirements.txt` && `requirements-dev.txt` for complete dependency list.

## References

- Bandit: https://github.com/PyCQA/bandit
- OWASP Cheat Sheets: https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets
- CWE Database: https://cwe.mitre.org/
- OSV Vulnerability Database: https://osv.dev/
- Python AST Documentation: https://docs.python.org/3/library/ast.html
- Python Package Advisory DB: https://github.com/pypa/advisory-database