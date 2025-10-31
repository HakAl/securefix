from .llm_factory import LLMFactory
from .llm_base import LLMConfig
from .llm_google import GoogleGenAIConfig, check_google_api_key
from .llm_ollama import OllamaConfig, check_ollama_available, get_available_ollama_models

# Conditionally import LlamaCPP if available
__all__ = [
    'LLMFactory',
    'LLMConfig',
    'GoogleGenAIConfig',
    'OllamaConfig',
    'check_google_api_key',
    'check_ollama_available',
    'get_available_ollama_models',
]

try:
    from .llm_llamacpp import (
        LlamaCPPConfig,
        check_llamacpp_available,
        validate_gguf_model,
        get_recommended_settings,
    )
    __all__.extend([
        'LlamaCPPConfig',
        'check_llamacpp_available',
        'validate_gguf_model',
        'get_recommended_settings',
    ])
    LLAMACPP_AVAILABLE = True
except ImportError:
    LLAMACPP_AVAILABLE = False

__all__.append('LLAMACPP_AVAILABLE')