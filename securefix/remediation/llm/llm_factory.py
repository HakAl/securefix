from typing import Optional
from .llm_base import LLMConfig
from .llm_google import GoogleGenAIConfig
from .llm_ollama import OllamaConfig

# Optional import for LlamaCPP
try:
    from .llm_llamacpp import LlamaCPPConfig

    LLAMACPP_AVAILABLE = True
except ImportError:
    LLAMACPP_AVAILABLE = False


class LLMFactory:
    """
    Factory for creating LLM configurations based on user preferences.

    This separates configuration logic from the RAG system itself.
    """

    @staticmethod
    def create_from_mode(
            mode: str,
            api_key: Optional[str] = None,
            model_name: Optional[str] = None,
            model_path: Optional[str] = None,
    ) -> LLMConfig:
        """
        Create LLM config from legacy mode string (for backward compatibility).

        Args:
            mode: "local", "google", or "llamacpp"
            api_key: API key for cloud providers
            model_name: Optional model override (for ollama/google)
            model_path: Path to GGUF model file (for llamacpp)

        Returns:
            Configured LLMConfig instance

        Raises:
            ValueError: If mode is invalid or required parameters missing
        """
        mode = mode.lower().strip()

        if mode == "local":
            return OllamaConfig(
                model_name=model_name or "llama3.2:3b"
            )

        elif mode == "google":
            if not api_key:
                raise ValueError("Google mode requires api_key parameter")
            return GoogleGenAIConfig(
                api_key=api_key,
                model_name=model_name or "gemini-2.0-flash-lite"
            )

        elif mode == "llamacpp":
            if not LLAMACPP_AVAILABLE:
                raise ValueError(
                    "LlamaCPP mode requires llama-cpp-python to be installed.\n"
                    "Install with: pip install llama-cpp-python\n"
                    "Or: pip install securefix[llamacpp]"
                )
            if not model_path:
                raise ValueError("LlamaCPP mode requires model_path parameter")
            return LlamaCPPConfig(model_path=model_path)

        else:
            valid_modes = "'local', 'google'"
            if LLAMACPP_AVAILABLE:
                valid_modes += ", 'llamacpp'"
            raise ValueError(
                f"Unknown mode: {mode}. "
                f"Valid options: {valid_modes}"
            )

    @staticmethod
    def create_google(
            api_key: str,
            model_name: str = "gemini-2.0-flash-lite",
            **kwargs
    ) -> GoogleGenAIConfig:
        """Convenience method for creating Google config."""
        return GoogleGenAIConfig(
            api_key=api_key,
            model_name=model_name,
            **kwargs
        )

    @staticmethod
    def create_ollama(
            model_name: str = "llama3.2:3b",
            **kwargs
    ) -> OllamaConfig:
        """Convenience method for creating Ollama config."""
        return OllamaConfig(
            model_name=model_name,
            **kwargs
        )

    @staticmethod
    def create_llamacpp(
            model_path: str,
            **kwargs
    ) -> "LlamaCPPConfig":
        """
        Convenience method for creating LlamaCPP config.

        Args:
            model_path: Path to GGUF model file
            **kwargs: Additional configuration parameters

        Returns:
            LlamaCPPConfig instance

        Raises:
            ValueError: If llama-cpp-python is not installed
        """
        if not LLAMACPP_AVAILABLE:
            raise ValueError(
                "LlamaCPP not available. "
                "Install with: pip install llama-cpp-python\n"
                "Or: pip install securefix[llamacpp]"
            )
        return LlamaCPPConfig(
            model_path=model_path,
            **kwargs
        )

    @staticmethod
    def is_llamacpp_available() -> bool:
        """Check if LlamaCPP support is available."""
        return LLAMACPP_AVAILABLE