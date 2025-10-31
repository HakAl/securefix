from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from langchain_core.language_models import BaseLanguageModel
from langchain_core.prompts import PromptTemplate
from .llm_base import LLMConfig


@dataclass(kw_only=True)
class LlamaCPPConfig(LLMConfig):
    """Configuration for local LlamaCPP models (GGUF format)."""

    model_path: str
    temperature: float = 0.1
    max_tokens: int = 600
    n_ctx: int = 2048  # Context window size
    n_threads: Optional[int] = None  # Auto-detect if None
    n_gpu_layers: int = 0  # Number of layers to offload to GPU (0 = CPU only)
    top_k: int = 40
    top_p: float = 0.9
    repeat_penalty: float = 1.1
    verbose: bool = False
    n_batch: int = 512

    def create_llm(self) -> BaseLanguageModel:
        """Create LlamaCPP LLM instance."""
        try:
            from langchain_community.llms import LlamaCpp
        except ImportError as e:
            raise ImportError(
                "LlamaCPP not available. "
                "Install with: pip install llama-cpp-python\n"
                "Or: pip install securefix[llamacpp]"
            ) from e

        # Validate model path exists
        model_path = Path(self.model_path)
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model file not found: {self.model_path}\n"
                f"Please download a GGUF model file first."
            )

        return LlamaCpp(
            model_path=str(model_path),
            temperature=self.temperature,
            max_tokens=self.max_tokens,
            n_ctx=self.n_ctx,
            n_threads=self.n_threads,
            n_gpu_layers=self.n_gpu_layers,
            top_k=self.top_k,
            top_p=self.top_p,
            repeat_penalty=self.repeat_penalty,
            verbose=self.verbose,
            n_batch=self.n_batch
        )

    def get_prompt_template(self) -> PromptTemplate:
        """Return concise prompt template optimized for local models."""
        return self.get_default_prompt_template()

    def get_display_name(self) -> str:
        model_name = Path(self.model_path).stem
        return f"LlamaCPP ({model_name})"


def check_llamacpp_available() -> bool:
    """
    Check if llama-cpp-python is installed.

    Returns:
        True if llama-cpp-python is available, False otherwise
    """
    try:
        from langchain_community.llms import LlamaCpp
        return True
    except ImportError:
        return False


def validate_gguf_model(model_path: str) -> tuple[bool, Optional[str]]:
    """
    Validate that a model file exists and is likely a GGUF file.

    Args:
        model_path: Path to the model file

    Returns:
        Tuple of (is_valid, error_message)
    """
    path = Path(model_path)

    if not path.exists():
        return False, f"Model file not found: {model_path}"

    if not path.is_file():
        return False, f"Path is not a file: {model_path}"

    # Check file extension (common GGUF extensions)
    valid_extensions = {'.gguf', '.bin'}
    if path.suffix.lower() not in valid_extensions:
        return False, f"Invalid file extension. Expected .gguf or .bin, got {path.suffix}"

    # Check file size (should be at least a few MB)
    size_mb = path.stat().st_size / (1024 * 1024)
    if size_mb < 10:
        return False, f"File too small ({size_mb:.1f} MB). GGUF models are typically much larger."

    return True, None


def get_recommended_settings(model_size_mb: float) -> dict:
    """
    Get recommended settings based on model size.

    Args:
        model_size_mb: Model file size in megabytes

    Returns:
        Dictionary of recommended settings
    """
    # Rough estimates based on model size
    if model_size_mb < 1000:  # ~1GB - small models (1B-3B params)
        return {
            'n_ctx': 2048,
            'n_threads': 4,
            'n_gpu_layers': 0,  # Can try GPU if available
            'max_tokens': 600,
        }
    elif model_size_mb < 4000:  # ~4GB - medium models (7B params)
        return {
            'n_ctx': 2048,
            'n_threads': 6,
            'n_gpu_layers': 0,
            'max_tokens': 500,
        }
    else:  # Large models (13B+ params)
        return {
            'n_ctx': 2048,
            'n_threads': 8,
            'n_gpu_layers': 0,  # Recommend GPU for large models
            'max_tokens': 400,
        }