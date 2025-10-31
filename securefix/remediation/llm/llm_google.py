from dataclasses import dataclass
from langchain_core.language_models import BaseLanguageModel
from langchain_core.prompts import PromptTemplate
from .llm_base import LLMConfig


@dataclass(kw_only=True)
class GoogleGenAIConfig(LLMConfig):
    """Configuration for Google Generative AI models."""

    api_key: str
    model_name: str = "gemini-2.0-flash-lite"
    temperature: float = 0.1
    max_tokens: int = 1000

    def create_llm(self) -> BaseLanguageModel:
        """Create Google Gemini LLM instance."""
        try:
            from langchain_google_genai import ChatGoogleGenerativeAI
            import google.generativeai as genai

            genai.configure(api_key=self.api_key)

            return ChatGoogleGenerativeAI(
                model=self.model_name,
                google_api_key=self.api_key,
                temperature=self.temperature,
                max_output_tokens=self.max_tokens,
            )
        except ImportError as e:
            raise ImportError(
                "Google Generative AI not available. "
                "Install with: pip install langchain-google-genai"
            ) from e

    def get_prompt_template(self) -> PromptTemplate:
        """Return detailed prompt template optimized for Gemini."""
        return self.get_default_prompt_template()

    def get_display_name(self) -> str:
        return f"Google {self.model_name}"


def check_google_api_key(api_key: str) -> bool:
    """
    Validate Google API key by attempting to configure.

    Args:
        api_key: Google API key to validate

    Returns:
        True if key appears valid, False otherwise
    """
    if not api_key or not isinstance(api_key, str) or len(api_key.strip()) == 0:
        return False

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        # Could add a test API call here if needed for deeper validation
        return True
    except Exception:
        return False