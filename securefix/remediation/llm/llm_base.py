from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from langchain_core.language_models import BaseLanguageModel
from langchain_core.prompts import PromptTemplate


@dataclass(kw_only=True)
class LLMConfig(ABC):
    """Base configuration for LLM providers."""

    temperature: float = field(default=0.1, init=False)
    max_tokens: int = field(default=1000, init=False)

    @abstractmethod
    def create_llm(self) -> BaseLanguageModel:
        """Create and return configured LLM instance."""
        pass

    @abstractmethod
    def get_prompt_template(self) -> PromptTemplate:
        """Return appropriate prompt template for this LLM."""
        pass

    @abstractmethod
    def get_display_name(self) -> str:
        """Return human-readable name for logging/UI."""
        pass

    def get_default_prompt_template(self) -> PromptTemplate:
        """
        Return default security prompt template.
        Can be overridden by specific implementations if needed.
        """
        template = """You are an expert security code reviewer. A Static Analysis tool detected a potential vulnerability in the following Python code.

**Vulnerability Details:**
Type: {finding_type}
Line: {line_number}
File: {file_path}
Severity: {severity}
CWE ID: {cwe_id}

**Vulnerable Code:**
```python
{original_code}
```

**Secure Coding Context (Retrieved from Knowledge Base):**
{context}

---

Based on the secure coding practices provided above, generate a response in JSON format with four keys:

1. 'suggested_fix': Syntactically correct, fixed code. Preserve original formatting/indentation as much as possible.
2. 'explanation': A brief explanation of why the original is vulnerable and how the fix helps (2-3 sentences)
3. 'confidence': Your confidence level ('High', 'Medium', or 'Low')
4. 'cwe_id': The relevant CWE identifier if applicable

**Important:** Respond with valid JSON only, no additional text."""

        return PromptTemplate(
            template=template,
            input_variables=["context", "finding_type", "line_number", "file_path",
                           "severity", "cwe_id", "original_code"]
        )