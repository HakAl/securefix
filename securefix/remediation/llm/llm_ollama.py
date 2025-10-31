from dataclasses import dataclass
from typing import List, Any
from langchain_core.language_models import BaseLanguageModel
from langchain_core.prompts import PromptTemplate
from .llm_base import LLMConfig


@dataclass(kw_only=True)
class OllamaConfig(LLMConfig):
    """Configuration for local Ollama models."""

    model_name: str = "llama3.2:3b"
    temperature: float = 0.1
    max_tokens: int = 600
    num_thread: int = 6
    num_gpu: int = 1
    top_k: int = 20
    top_p: float = 0.9
    repeat_penalty: float = 1.1

    def create_llm(self) -> BaseLanguageModel:
        """Create Ollama LLM instance."""
        try:
            from langchain_ollama import OllamaLLM

            return OllamaLLM(
                model=self.model_name,
                temperature=self.temperature,
                num_predict=self.max_tokens,
                num_thread=self.num_thread,
                num_gpu=self.num_gpu,
                top_k=self.top_k,
                top_p=self.top_p,
                repeat_penalty=self.repeat_penalty,
            )
        except ImportError as e:
            raise ImportError(
                "Ollama not available. "
                "Install with: pip install langchain-ollama"
            ) from e

    def get_prompt_template(self) -> PromptTemplate:
        """Return concise prompt template optimized for local models."""
        return self.get_default_prompt_template()

    def get_display_name(self) -> str:
        return f"Ollama {self.model_name}"


def check_ollama_available() -> bool:
    """
    Check if Ollama is installed and running.

    Returns:
        True if Ollama is accessible, False otherwise
    """
    try:
        import ollama
        ollama.list()
        return True
    except Exception:
        return False


def get_available_ollama_models() -> List[str]:
    """
    Fetches the names of all locally available Ollama models.
    This version is highly defensive to handle variations in the ollama library's output.
    """
    try:
        import ollama
        response: Any = ollama.list()
        models_list: List[Any] = []

        if isinstance(response, dict) and 'models' in response:
            models_list = response['models']
        elif hasattr(response, 'models'):
            models_list = response.models
        else:
            print(
                f"\n[DEBUG] Could not find a 'models' list in the response from ollama.list(). Response: {response}\n")
            return []

        if not isinstance(models_list, list):
            print(f"\n[DEBUG] The 'models' field found was not a list. Found: {models_list}\n")
            return []

        model_names: List[str] = []
        for model_item in models_list:
            name = None
            if isinstance(model_item, dict):
                name = model_item.get('name') or model_item.get('model')
            elif hasattr(model_item, 'name'):
                name = model_item.name
            elif hasattr(model_item, 'model'):
                name = model_item.model

            if name:
                model_names.append(name)

        if not model_names and models_list:
            print("\n[DEBUG] Found a models list, but could not extract any model names from it.\n")

        return model_names

    except Exception as e:
        print(f"\n[DEBUG] An error occurred while executing ollama.list(): {e}\n")
        if "Connection refused" in str(e):
            print("[INFO] Could not connect to Ollama. Please ensure the Ollama application is running.")
        return []