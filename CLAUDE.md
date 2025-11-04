# SecureFix - CLAUDE.md

## Overview
Python SAST tool combining Bandit vulnerability detection with RAG-powered remediation. Uses hybrid search over security corpus (CWE, OWASP) to generate contextual fixes via LLM.

## Architecture
- `sast/` - Bandit-based detection (SQL injection, secrets, XSS, etc)
- `cve/` - OSV database scanning for dependencies
- `remediation/` - RAG chain (BM25 + vector search → LLM fix generation)
- `cli/` - Click-based commands: `scan`, `fix`, `ingest`

## Key Files
- `sast/bandit_mapper.py` - Vulnerability type mappings
- `remediation/rag_chain.py` - Prompt engineering & fix generation
- `remediation/llm_factory.py` - LLM backend switching (Ollama/Gemini/LlamaCPP)
- `remediation/corpus/` - Security knowledge base (must run `securefix ingest` first)

## Development Rules
- **Security first**: Never introduce real vulnerabilities outside `vulnerable/` test directory
- **Testing**: Use pytest markers (`@pytest.mark.unit`, `@pytest.mark.integration`)
- **Config**: CLI args > env vars (`.env`) > defaults
- **RAG changes**: Rebuild vector DB with `securefix ingest --rebuild`

## Common Tasks
**Add vulnerability detection**: Check `bandit_mapper.py` first; Bandit handles most cases
**Improve fixes**: Edit prompts in `remediation/rag_chain.py`
**Add LLM backend**: Modify `llm_factory.py` and `cli/fix.py`
**Extend corpus**: Add files to `remediation/corpus/` (.csv/.md/.yaml), then rebuild

## Quick Debug
```bash
# Test pipeline
securefix scan vulnerable/ -o test.json
securefix fix test.json --interactive

# Check vector DB
python -c "from remediation.vector_store import get_vector_store; print(get_vector_store()._collection.count())"

# LLM issues
ollama list  # Check local models
echo $GOOGLE_API_KEY  # Verify cloud setup
```

## Critical Notes
- Test files in `vulnerable/` are intentionally insecure
- Remediation suggestions are advisory only - always review
- Requires 3B+ parameter models for reliable results
- Cache disabled with `--no-cache` (slower but fresher results)