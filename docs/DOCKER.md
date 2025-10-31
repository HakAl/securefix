# SecureFix Docker Guide

## Quick Start

### Build the Image

```bash
docker build -t securefix:latest .
```

### Run with Docker Compose (Recommended)

```bash
# Start SecureFix
docker-compose up -d

# Run a scan
docker-compose run --rm securefix scan /scan --output /data/reports/report.json

# Generate fixes
docker-compose run --rm securefix fix /data/reports/report.json --output /data/fixes/fixes.json

# Stop services
docker-compose down
```

## Usage Examples

### 1. Scan Code

```bash
# Scan directory mounted at /scan
docker run --rm \
  -v $(pwd)/vulnerable:/scan:ro \
  -v $(pwd)/data/reports:/data/reports \
  securefix:latest scan /scan --output /data/reports/report.json
```

### 2. Generate Fixes (LlamaCPP Mode)

```bash
# First, build the vector database (one-time setup)
docker run --rm \
  -v $(pwd)/data/chroma_db:/data/chroma_db \
  securefix:latest ingest --persist-dir /data/chroma_db

# Generate fixes using LlamaCPP
docker run --rm \
  -v $(pwd)/models:/models:ro \
  -v $(pwd)/data:/data \
  -e LLAMACPP_MODEL_PATH=/models/qwen2.5-3b-instruct-q4_k_m.gguf \
  -e LLAMACPP_N_THREADS=14 \
  securefix:latest fix /data/reports/report.json \
    --llm-mode llamacpp \
    --model-path /models/qwen2.5-3b-instruct-q4_k_m.gguf \
    --output /data/fixes/fixes.json
```

### 3. Using Google Gemini

```bash
docker run --rm \
  -v $(pwd)/data:/data \
  -e GOOGLE_API_KEY=your_api_key_here \
  securefix:latest fix /data/reports/report.json \
    --llm-mode google \
    --output /data/fixes/fixes.json
```

### 4. Using Ollama

```bash
# Start Ollama service
docker-compose --profile ollama up -d ollama

# Pull a model in Ollama
docker exec ollama ollama pull llama3.2:3b

# Run SecureFix with Ollama
docker run --rm \
  --network container:ollama \
  -v $(pwd)/data:/data \
  securefix:latest fix /data/reports/report.json \
    --llm-mode local \
    --model-name llama3.2:3b \
    --output /data/fixes/fixes.json
```

## Directory Structure

```
.
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── models/                          # Mount your GGUF models here
│   └── qwen2.5-3b-instruct-q4_k_m.gguf
├── vulnerable/                      # Your code to scan
│   └── app.py
├── data/
│   ├── reports/                     # Scan reports
│   ├── fixes/                       # Remediation outputs
│   └── chroma_db/                   # Vector database (persistent)
└── custom_corpus/                   # Optional custom security corpus
```

## Environment Variables

Configure SecureFix via environment variables in `docker-compose.yml` or `-e` flags:

### LLM Configuration
```bash
MODE=local                           # local, google, or llamacpp
GOOGLE_API_KEY=your_key              # For Google Gemini
MODEL_NAME=llama3.2:3b              # For Ollama/Google
```

### LlamaCPP Settings
```bash
LLAMACPP_MODEL_PATH=/models/model.gguf
LLAMACPP_N_CTX=2048
LLAMACPP_N_THREADS=14
LLAMACPP_N_GPU_LAYERS=0
LLAMACPP_N_BATCH=512
```

### Retriever Settings
```bash
VECTOR_K=4
VECTOR_FETCH_K=12
BM25_TOP_K=2
```

## Volume Mounts

### Required Volumes

- `/scan` - Your code to scan (read-only recommended)
- `/data/reports` - Output directory for scan reports
- `/data/fixes` - Output directory for remediation suggestions
- `/data/chroma_db` - Persistent vector database

### Optional Volumes

- `/models` - GGUF model files for LlamaCPP (read-only)
- `/app/remediation/corpus` - Custom security corpus

## Performance Tuning

### CPU Resources

```yaml
deploy:
  resources:
    limits:
      cpus: '14'        # Match your physical cores
      memory: 16G
```

### LlamaCPP Optimization

```bash
# Adjust based on your hardware
LLAMACPP_N_THREADS=14      # Physical CPU cores
LLAMACPP_N_BATCH=512       # Increase for better throughput
LLAMACPP_N_GPU_LAYERS=0    # Set > 0 if GPU available
```

## Common Workflows

### Full Scan + Fix Pipeline

```bash
#!/bin/bash
# scan_and_fix.sh

# 1. Scan code
docker-compose run --rm securefix scan /scan \
  --output /data/reports/report.json

# 2. Generate fixes
docker-compose run --rm securefix fix /data/reports/report.json \
  --llm-mode llamacpp \
  --output /data/fixes/fixes.json

# 3. Review results
cat data/fixes/fixes.json | jq '.summary'
```

### CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build SecureFix
        run: docker build -t securefix:latest .
      
      - name: Scan Code
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/scan:ro \
            -v ${{ github.workspace }}/reports:/data/reports \
            securefix:latest scan /scan \
              --output /data/reports/report.json
      
      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: reports/report.json
```

## Troubleshooting

### Issue: "Model file not found"
```bash
# Ensure model is mounted correctly
docker run --rm -v $(pwd)/models:/models:ro securefix:latest ls -la /models
```

### Issue: "Permission denied"
```bash
# Check file ownership
chown -R 1000:1000 ./data ./models
```

### Issue: Slow inference
```bash
# Increase thread count and batch size
-e LLAMACPP_N_THREADS=<your_cpu_cores>
-e LLAMACPP_N_BATCH=1024
```

### Issue: Out of memory
```bash
# Reduce resource usage
-e LLAMACPP_N_CTX=1024        # Smaller context window
-e LLAMACPP_N_BATCH=256       # Smaller batch size
# Or use a smaller model (e.g., 1B instead of 3B)
```

## Building for Production

### Multi-architecture Build

```bash
# Build for multiple platforms
docker buildx create --use
docker buildx build --platform linux/amd64,linux/arm64 -t securefix:latest .
```

### Optimized Production Build

```bash
# Build with specific optimizations
docker build \
  --build-arg LLAMACPP_CMAKE_ARGS="-DLLAMA_NATIVE=on" \
  -t securefix:optimized .
```

## Security Best Practices

1. **Run as non-root** - Container runs as user `securefix` (UID 1000)
2. **Read-only mounts** - Mount scan targets as read-only (`:ro`)
3. **Resource limits** - Set CPU and memory limits in compose file
4. **Secrets management** - Use Docker secrets or env files for API keys
5. **Network isolation** - Use custom networks to isolate services