# SecureFix

A static Python application security testing (SAST) suite with intelligent remediation powered by retrieval-augmented generation (RAG).
SecureFix combines deterministic vulnerability detection with context-aware fix suggestions to help developers identify and resolve security issues efficiently.

## Overview

SecureFix bridges rule-based precision and AI-driven guidance through two core capabilities:

- **Static Analysis Engine**: Deterministic detection of SQL injection, hardcoded secrets, and dependency vulnerabilities using AST analysis and CVE databases
- **Smart Remediation**: RAG-powered fix generation that retrieves relevant security patterns and synthesizes contextual remediation guidance

## Features

### Detection Capabilities

- **Code-level vulnerabilities** via Abstract Syntax Tree (AST) analysis
  - SQL injection through unsafe query construction
  - Hardcoded secrets (API keys, tokens, credentials)
- **Dependency vulnerabilities** via CVE scanning
  - Hardcoded high-confidence vulnerabilities
  - Real-time lookup via OSV database API

### Remediation Capabilities

- **Semantic retrieval** of relevant security patterns using hybrid BM25 + vector search
- **Context-aware fix generation** with explanations and confidence scoring
- **Multi-LLM support** for both local (Ollama) and cloud-based (Google Gen AI) processing
- **Query caching** for performance optimization

## Architecture

```
securefix/
├── sast/
│   ├── scanner.py              # AST-based code analysis
│   ├── detectors/
│   │   ├── sql_injection.py    # SQLi detection via data flow analysis
│   │   ├── secrets.py          # Pattern-based secret detection
├── cve/
│   ├── scanner.py              # Dependency vulnerability scanning
│   ├── db.py                   # CVE database with OSV integration
├── remediation/
│   ├── corpus/                 # Security fix pattern knowledge base
│   ├── remediation_engine.py   # RAG-based fix generation
│   ├── fix_knowledge_store.py  # Vector store for security patterns
│   ├── vulnerability_retriever.py  # Hybrid retrieval pipeline
│   ├── llm_factory.py          # Multi-LLM provider support
├── tests/
│   ├── test_sast.py
│   ├── test_remediation.py
├── securefix.py                # CLI entry point
└── requirements.txt
```

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
ollama pull phi3:mini  # or llama3.1:8b-instruct-q4_K_M for better quality
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
```

### Output Format

**Vulnerability Report**:
```json
{
  "summary": {
    "total_findings": 3,
    "by_severity": {"critical": 1, "high": 2},
    "total_cve_findings": 0,
    "scan_timestamp": "2025-10-28T20:41:38.642590"
  },
  "findings": [
    {
      "type": "SQL Injection",
      "file": "app.py",
      "line": 23,
      "severity": "High",
      "confidence": "High",
      "cwe_id": "CWE-89",
      "snippet": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')"
    }
  ],
  "cve_findings": []
}
```

**Remediation Output**:
```json
{
  "finding_id": "SQL-001",
  "original_code": "cursor.execute(f'SELECT * FROM users WHERE id={uid}')",
  "suggested_fix": "cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))",
  "explanation": "Parameterized queries separate SQL code from user data...",
  "confidence": "High",
  "cwe_id": "CWE-89"
}
```

## Technical Approach

### Detection Pipeline

1. **AST Analysis**: Parse Python code into abstract syntax tree
2. **Data Flow Tracking**: Identify paths from user input to sensitive sinks
3. **Pattern Matching**: Apply regex rules for secret detection
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

## Design Decisions

**Why deterministic detection?** Rule-based and AST analysis ensures reproducibility and zero false negatives on known patterns, critical for CI/CD integration.

**Why RAG for remediation?** Retrieval allows the system to stay current with evolving security best practices without retraining. Fixes are traceable to authoritative sources like OWASP.

**Why hybrid retrieval?** Combining BM25 (keyword matching) with semantic search balances exact pattern matching with conceptual similarity.

**Why decoupled architecture?** Separating detection (deterministic, verifiable) from remediation (generative, advisory) allows security teams to trust findings while providing developers with helpful AI guidance.

## Limitations

- Python-only support in current implementation
- Limited to surface-level data flow analysis (no inter-procedural analysis)
- Remediation suggestions are advisory, not guaranteed safe
- Local LLM mode requires sufficient RAM (8GB+ recommended)

## Future Work

- Multi-language support (JavaScript, Java, Go)
- Runtime Application Self-Protection (RASP) integration
- Machine learning for false positive reduction
- Inter-procedural data flow analysis

## Dependencies

- langchain: RAG framework and LLM orchestration
- chromadb: Vector storage for security patterns
- sentence-transformers: Semantic embedding generation
- ollama: Local LLM support
- click: CLI framework

See `requirements.txt` && `requirements-dev.txt` for complete dependency list.

## References

- OWASP Cheat Sheets: https://github.com/OWASP/CheatSheetSeries/tree/master/cheatsheets
- CWE Database: https://cwe.mitre.org/
- OSV Vulnerability Database: https://osv.dev/
- Python AST Documentation: https://docs.python.org/3/library/ast.html
- Python Package Advisory DB: https://github.com/pypa/advisory-database