import re
import time
from remediation.fix_knowledge_store import DocumentStore
from langchain.callbacks.base import BaseCallbackHandler
from langchain.chains import RetrievalQA
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.runnables import RunnableSerializable
from remediation.llm_factory import LLMConfig
from remediation.fix_cache import SemanticQueryCache
from typing import Any, Dict, List, Optional, Callable

# --- NLTK Integration for Preprocessing ---
try:
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize

    STOP_WORDS = set(stopwords.words("english"))
except ImportError:
    print("Warning: 'nltk' library not found. Preprocessing will be limited.")
    print("Please install it with: pip install nltk")
    STOP_WORDS = set()
except LookupError:
    print("=" * 80)
    print("nltk data (stopwords, punkt) not found. Please run the following in your Python environment:")
    print("import nltk; nltk.download('stopwords'); nltk.download('punkt')")
    print("=" * 80)
    STOP_WORDS = set()


class TokenStreamCallbackHandler(BaseCallbackHandler):
    """A custom callback handler to stream tokens to a callback function."""

    def __init__(self, token_callback: Callable[[str], None]):
        self.token_callback = token_callback

    def on_llm_new_token(self, token: str, **kwargs: Any) -> None:
        """Run on new LLM token. Only available when streaming is enabled."""
        self.token_callback(token)


class RemediationEngine:
    """
    Security vulnerability remediation system using RAG.
    Delegates LLM configuration and prompting to LLMConfig.
    """

    def __init__(
            self,
            document_store: DocumentStore,
            llm_config: LLMConfig,
            enable_cache: bool = True,
            cache_similarity_threshold: float = 0.85,
            cache_max_size: int = 100,
    ):
        self.document_store = document_store
        self.llm_config = llm_config
        self.llm = llm_config.create_llm()
        self.prompt = llm_config.get_prompt_template()
        self._retriever = self.document_store.get_retriever()
        self._chain: Optional[RunnableSerializable] = None

        self.enable_cache = enable_cache
        if self.enable_cache:
            self.cache = SemanticQueryCache(
                similarity_threshold=cache_similarity_threshold,
                max_size=cache_max_size
            )
            self.cache.embeddings = self.document_store.get_embedding_function()
        else:
            self.cache = None

        print(f"Loaded LLM: {llm_config.get_display_name()}")
        if self.enable_cache:
            print(f"Semantic cache enabled (threshold: {cache_similarity_threshold})")

    def _get_chain(self) -> RunnableSerializable:
        if self._chain is None:
            self._chain = RetrievalQA.from_chain_type(
                llm=self.llm,
                chain_type="stuff",
                retriever=self._retriever,
                chain_type_kwargs={"prompt": self.prompt},
                return_source_documents=True,
            )
        return self._chain

    def generate_fix(self, vulnerability_finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a security fix for a specific vulnerability.

        Args:
            vulnerability_finding: Dictionary containing:
                - type: Vulnerability type (required)
                - snippet: Code snippet with vulnerability (required)
                - line_number: Line number (optional)
                - file_path: File path (optional)
                - severity: Severity level (optional)
                - cwe_id: CWE identifier (optional)

        Returns:
            Dictionary with fix details and source documents
        """
        # Build cache key from vulnerability fingerprint
        cache_key = f"{vulnerability_finding.get('type', '')}|{vulnerability_finding.get('snippet', '')[:200]}"

        if self.enable_cache and self.cache:
            cached_result = self.cache.get(cache_key)
            if cached_result:
                print("Cache hit!")
                return cached_result

        t0 = time.perf_counter()
        try:
            # Extract variables for prompt template
            prompt_vars = {
                "finding_type": vulnerability_finding.get('type', 'Unknown'),
                "line_number": vulnerability_finding.get('line_number', 'Unknown'),
                "file_path": vulnerability_finding.get('file_path', 'Unknown'),
                "severity": vulnerability_finding.get('severity', 'Medium'),
                "cwe_id": vulnerability_finding.get('cwe_id', ''),
                "original_code": vulnerability_finding.get('snippet', ''),
            }

            # Build a query string for retrieval (not the full dict!)
            # This is what the retriever uses to find relevant documents
            query_string = f"{prompt_vars['finding_type']} {prompt_vars['cwe_id']} vulnerability security fix"

            # Get relevant documents manually
            docs = self._retriever.invoke(query_string)

            # Build context from retrieved documents
            context = "\n\n".join([doc.page_content for doc in docs])

            # Add context to prompt vars
            prompt_vars["context"] = context

            # Now invoke LLM with the formatted prompt
            formatted_prompt = self.prompt.format(**prompt_vars)
            llm_result = self.llm.invoke(formatted_prompt)

            final_result = {
                "answer": llm_result if isinstance(llm_result, str) else llm_result.content,
                "source_documents": docs,
            }

            if self.enable_cache and self.cache:
                self.cache.set(cache_key, final_result)

            t1 = time.perf_counter()
            print(f"Fix generation took {t1 - t0:.2f}s")
            return final_result

        except Exception as e:
            error_msg = self._format_error_message(e)
            raise RemediationEngineError(error_msg) from e

    def clear_cache(self):
        """Clear the semantic cache"""
        if self.cache:
            self.cache.cache.clear()
            print("Cache cleared")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        if not self.cache:
            return {"cache_enabled": False}

        return {
            "cache_enabled": True,
            "cache_size": len(self.cache.cache),
            "max_size": self.cache.max_size,
            "similarity_threshold": self.cache.threshold
        }

    def _format_error_message(self, error: Exception) -> str:
        if isinstance(error, RemediationEngineError):
            return str(error)

        base_msg = f"Error generating security fix: {str(error)}"
        llm_name = self.llm_config.get_display_name().lower()

        if "ollama" in llm_name:
            base_msg += (
                "\n\n Troubleshooting tips for Ollama:"
                "\n  1. Ensure Ollama is running (check with: ollama list)"
                "\n  2. Verify your model is downloaded (e.g., ollama pull llama3.2:3b)"
                "\n  3. Check if Ollama service is accessible"
            )
        elif "google" in llm_name or "gemini" in llm_name:
            base_msg += (
                "\n\n Troubleshooting tips for Google Gemini:"
                "\n  1. Verify your API key is valid"
                "\n  2. Check your internet connection"
                "\n  3. Ensure you have API quota remaining"
            )

        return base_msg

    def get_llm_info(self) -> str:
        """Get human-readable LLM information."""
        return self.llm_config.get_display_name()


class RemediationEngineError(Exception):
    """Custom exception for RAG system errors."""
    pass