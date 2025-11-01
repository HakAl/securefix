# LlamaCPP Integration Guide

SecureFix supports optional local model inference using `llama-cpp-python` for running GGUF models without requiring Ollama.

## Installation

### Basic Installation (without LlamaCPP)
```bash
pip install securefix
```

### With LlamaCPP Support
```bash
# Install with LlamaCPP support
pip install securefix[llamacpp]

# Or install separately
pip install llama-cpp-python
```

### GPU Acceleration (Optional)

For CUDA (NVIDIA GPUs):
```bash
CMAKE_ARGS="-DLLAMA_CUBLAS=on" pip install llama-cpp-python
```

For Metal (Apple Silicon):
```bash
CMAKE_ARGS="-DLLAMA_METAL=on" pip install llama-cpp-python
```

For more installation options, see [llama-cpp-python documentation](https://github.com/abetlen/llama-cpp-python).

## Downloading Models

You'll need to download GGUF model files. Here are some recommended sources:
Try this specialist: https://huggingface.co/cmonplz/Qwen-3B-SAST-Python-Remediation-GGUF

### Recommended Models for Security Analysis

1. **Llama 3.2 3B (Quantized)**
   - Size: ~2GB
   - Good balance of speed and quality
   - Download: Search for "llama-3.2-3b-instruct GGUF" on Hugging Face

2. **Phi-3 Mini**
   - Size: ~2GB
   - Fast and efficient
   - Download: Search for "Phi-3-mini GGUF" on Hugging Face

3. **Mistral 7B**
   - Size: ~4GB
   - Higher quality, slower
   - Download: Search for "Mistral-7B-Instruct GGUF" on Hugging Face

### Quantization Levels

GGUF models come in different quantization levels (Q2, Q4, Q5, Q8):
- **Q4_K_M**: Good balance (recommended for most users)
- **Q5_K_M**: Better quality, larger size
- **Q8_0**: Highest quality, largest size

## Usage

### Basic Usage

```python
from securefix.remediation.llm import LLMFactory

# Check if LlamaCPP is available
if LLMFactory.is_llamacpp_available():
    config = LLMFactory.create_llamacpp(
        model_path="models/llama-3.2-3b-instruct.Q4_K_M.gguf"
    )
    llm = config.create_llm()
else:
    print("LlamaCPP not installed")
```

### With Custom Settings

```python
from securefix.remediation.llm import LLMFactory

config = LLMFactory.create_llamacpp(
    model_path="models/llama-3.2-3b-instruct.Q4_K_M.gguf",
    temperature=0.1,
    max_tokens=600,
    n_ctx=2048,        # Context window
    n_threads=6,       # CPU threads
    n_gpu_layers=35,   # GPU offloading (if GPU support enabled)
)

llm = config.create_llm()
```

### Validation and Recommendations

```python
from securefix.remediation.llm import (
    validate_gguf_model,
    get_recommended_settings,
)
from pathlib import Path

model_path = "models/my-model.gguf"

# Validate model file
is_valid, error = validate_gguf_model(model_path)
if not is_valid:
    print(f"Invalid model: {error}")
    exit(1)

# Get recommended settings based on model size
size_mb = Path(model_path).stat().st_size / (1024 * 1024)
settings = get_recommended_settings(size_mb)
print(f"Recommended settings: {settings}")

# Create config with recommendations
config = LLMFactory.create_llamacpp(
    model_path=model_path,
    **settings
)
```

### Mode-Based Factory

```python
from securefix.remediation.llm import LLMFactory

# Using mode string
config = LLMFactory.create_from_mode(
    mode="llamacpp",
    model_path="models/llama-3.2-3b-instruct.Q4_K_M.gguf"
)
```

### Graceful Fallback

```python
from securefix.remediation.llm import LLMFactory, LLAMACPP_AVAILABLE

if LLAMACPP_AVAILABLE:
    print("Using LlamaCPP for local inference")
    config = LLMFactory.create_llamacpp(
        model_path="models/llama-3.2-3b-instruct.Q4_K_M.gguf"
    )
else:
    print("Falling back to Ollama")
    config = LLMFactory.create_ollama(model_name="llama3.2:3b")
```

## File Organization

Recommended directory structure:
```
your_project/
├── models/                         # Git-ignored
│   ├── llama-3.2-3b-instruct.Q4_K_M.gguf
│   └── mistral-7b-instruct.Q4_K_M.gguf
├── .gitignore                      # Includes *.gguf
└── your_script.py
```

The following patterns are already in your `.gitignore`:
```gitignore
# LLM Model files
*.gguf
*.bin
*.safetensors
models/
```

## Performance Tips

### CPU-Only Systems
- Use Q4_K_M quantization for best speed/quality balance
- Set `n_threads` to number of physical cores (not logical)
- Use smaller models (3B parameters or less)

### GPU Systems
- Use `n_gpu_layers` to offload layers to GPU
- Start with all layers: `n_gpu_layers=-1` (automatically uses all)
- Monitor VRAM usage and adjust if needed

### Context Window
- Smaller `n_ctx` = faster inference
- Default 2048 is good for most security analysis tasks
- Increase only if analyzing very large code blocks

## Comparison: LlamaCPP vs Ollama

| Feature | LlamaCPP | Ollama |
|---------|----------|--------|
| Installation | Python package | Separate application |
| Model Format | GGUF files | Managed internally |
| GPU Support | Manual setup | Automatic |
| Memory Usage | Lower | Higher |
| Setup Complexity | Higher | Lower |
| Flexibility | More control | Less control |

**Use LlamaCPP when:**
- You want fine-grained control over inference
- You're embedding in a Python application
- You want to minimize dependencies
- You're running in constrained environments

**Use Ollama when:**
- You want easy model management
- You prefer a managed service
- You want automatic GPU detection
- You're okay with an additional service

## Troubleshooting

### "LlamaCPP not available"
```bash
# Install the package
pip install llama-cpp-python
```

### "Model file not found"
- Ensure the model file exists at the specified path
- Check that the path is absolute or relative to your working directory
- Verify the file has `.gguf` or `.bin` extension

### "File too small"
- GGUF models are typically several GB in size
- If your file is under 10MB, it may be corrupted
- Re-download the model

### Slow Inference
- Reduce `n_ctx` (context window)
- Use a more quantized model (Q4 instead of Q8)
- Use a smaller model (3B instead of 7B)
- Enable GPU acceleration if available

### Out of Memory
- Use a smaller model
- Reduce `n_ctx`
- If using GPU, reduce `n_gpu_layers`
- Close other applications

## Testing

Run tests for LlamaCPP integration:
```bash
# Run all tests
pytest tests/test_llm_llamacpp.py -v

# Run only if LlamaCPP is installed
pytest tests/test_llm_llamacpp.py -v -m "not skipif"

# Skip LlamaCPP tests
pytest -v -k "not llamacpp"
```

## Additional Resources

- [llama-cpp-python GitHub](https://github.com/abetlen/llama-cpp-python)
- [GGUF Format Specification](https://github.com/ggerganov/ggml/blob/master/docs/gguf.md)
- [Hugging Face Model Hub](https://huggingface.co/models?library=gguf)
- [Quantization Explained](https://huggingface.co/docs/transformers/main/en/quantization)