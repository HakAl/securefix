import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path so we can import modules from remediation/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from remediation.llm_factory import (
    LLMFactory,
    GoogleGenAIConfig,
    OllamaConfig,
    check_ollama_available,
)


class TestLLMFactory:
    """Test LLM factory methods."""

    def test_create_from_mode_local(self):
        """Test creating Ollama config from mode string."""
        config = LLMFactory.create_from_mode(mode="local")

        assert isinstance(config, OllamaConfig)
        # Flexible assertion - accepts any model name
        assert isinstance(config.model_name, str)
        assert len(config.model_name) > 0
        assert config.temperature >= 0.0

    def test_create_from_mode_google(self):
        """Test creating Google config from mode string."""
        config = LLMFactory.create_from_mode(
            mode="google",
            api_key="test-key"
        )

        assert isinstance(config, GoogleGenAIConfig)
        assert config.api_key == "test-key"
        assert isinstance(config.model_name, str)

    def test_create_from_mode_invalid_raises(self):
        """Test that invalid mode raises ValueError."""
        with pytest.raises(ValueError, match="Unknown mode"):
            LLMFactory.create_from_mode(mode="invalid")

    def test_create_from_mode_google_without_key_raises(self):
        """Test that Google mode without API key raises ValueError."""
        with pytest.raises(ValueError, match="requires api_key"):
            LLMFactory.create_from_mode(mode="google")

    def test_create_ollama_with_custom_params(self):
        """Test creating Ollama config with custom parameters."""
        config = LLMFactory.create_ollama(
            model_name="phi3:mini",
            temperature=0.3,
            num_thread=8,
        )

        assert config.model_name == "phi3:mini"
        assert config.temperature == 0.3
        assert config.num_thread == 8

    def test_create_google_with_custom_model(self):
        """Test creating Google config with custom model."""
        config = LLMFactory.create_google(
            api_key="test-key",
            model_name="gemini-1.5-pro"
        )

        assert config.model_name == "gemini-1.5-pro"


class TestGoogleGenAIConfig:
    """Test Google Gemini configuration."""

    def test_get_display_name(self):
        """Test display name formatting."""
        config = GoogleGenAIConfig(
            api_key="test",
            model_name="gemini-2.0-flash-lite"
        )
        display_name = config.get_display_name()
        assert isinstance(display_name, str)
        assert "gemini" in display_name.lower() or "google" in display_name.lower()

    def test_get_prompt_template(self):
        """Test prompt template generation for security fixes."""
        config = GoogleGenAIConfig(api_key="test")
        template = config.get_prompt_template()

        # Check that required variables for security remediation are present
        required_vars = [
            "context",
            "finding_type",
            "line_number",
            "file_path",
            "severity",
            "cwe_id",
            "original_code"
        ]

        for var in required_vars:
            assert var in template.input_variables, f"Missing variable: {var}"

        assert isinstance(template.template, str)
        assert len(template.template) > 0

        # Verify security-specific content in template
        assert "vulnerability" in template.template.lower() or "security" in template.template.lower()
        assert "json" in template.template.lower()  # Should request JSON output

    @patch('langchain_google_genai.ChatGoogleGenerativeAI')
    @patch('google.generativeai.configure')
    def test_create_llm(self, mock_genai_configure, mock_chat_class):
        """Test LLM creation with mocked dependencies."""
        config = GoogleGenAIConfig(
            api_key="test-key",
            model_name="gemini-2.0-flash-lite",
            temperature=0.2,
            max_tokens=500
        )

        mock_llm = Mock()
        mock_chat_class.return_value = mock_llm

        llm = config.create_llm()

        # Verify genai.configure was called with api_key
        mock_genai_configure.assert_called_once()
        assert mock_genai_configure.call_args[1]['api_key'] == "test-key"

        # Verify ChatGoogleGenerativeAI was instantiated
        mock_chat_class.assert_called_once()
        call_kwargs = mock_chat_class.call_args[1]
        assert call_kwargs['model'] == "gemini-2.0-flash-lite"
        assert call_kwargs['google_api_key'] == "test-key"

        assert llm == mock_llm


class TestOllamaConfig:
    """Test Ollama configuration."""

    def test_get_display_name(self):
        """Test display name formatting."""
        config = OllamaConfig(model_name="test-model")
        display_name = config.get_display_name()
        assert isinstance(display_name, str)
        assert "test-model" in display_name or "ollama" in display_name.lower()

    def test_get_prompt_template(self):
        """Test prompt template generation for security fixes."""
        config = OllamaConfig()
        template = config.get_prompt_template()

        # Check that required variables for security remediation are present
        required_vars = [
            "context",
            "finding_type",
            "line_number",
            "file_path",
            "severity",
            "cwe_id",
            "original_code"
        ]

        for var in required_vars:
            assert var in template.input_variables, f"Missing variable: {var}"

        assert isinstance(template.template, str)

        # Verify security-specific content in template
        assert "vulnerability" in template.template.lower() or "security" in template.template.lower()

    @patch('langchain_ollama.OllamaLLM')
    def test_create_llm(self, mock_ollama_class):
        """Test Ollama LLM creation."""
        config = OllamaConfig(
            model_name="phi3:mini",
            temperature=0.2,
            num_thread=4,
        )

        mock_llm = Mock()
        mock_ollama_class.return_value = mock_llm

        llm = config.create_llm()

        mock_ollama_class.assert_called_once()
        call_kwargs = mock_ollama_class.call_args[1]

        assert call_kwargs['model'] == "phi3:mini"
        assert call_kwargs['temperature'] == 0.2
        assert call_kwargs['num_thread'] == 4
        assert llm == mock_llm

    def test_default_parameters_exist(self):
        """Test that default parameters are set."""
        config = OllamaConfig()

        # Just verify attributes exist and have reasonable values
        assert hasattr(config, 'model_name')
        assert isinstance(config.model_name, str)
        assert len(config.model_name) > 0
        assert hasattr(config, 'temperature')
        assert 0.0 <= config.temperature <= 2.0
        assert hasattr(config, 'max_tokens')
        assert config.max_tokens > 0


class TestUtilityFunctions:
    """Test utility functions."""

    @patch('ollama.list')
    def test_check_ollama_available_success(self, mock_ollama_list):
        """Test Ollama availability check when available."""
        mock_ollama_list.return_value = []

        result = check_ollama_available()

        assert result is True
        mock_ollama_list.assert_called_once()

    @patch('ollama.list')
    def test_check_ollama_available_failure(self, mock_ollama_list):
        """Test Ollama availability check when not available."""
        mock_ollama_list.side_effect = Exception("Connection failed")

        result = check_ollama_available()

        assert result is False


class TestConfigIntegration:
    """Integration tests showing how configs work together."""

    def test_switching_between_configs(self):
        """Test that different configs produce different display names."""
        ollama = LLMFactory.create_ollama(model_name="phi3:mini")
        google = LLMFactory.create_google(api_key="test", model_name="gemini-2.0-flash-lite")

        ollama_name = ollama.get_display_name()
        google_name = google.get_display_name()

        # Verify they're different configs
        assert ollama_name != google_name
        assert isinstance(ollama_name, str)
        assert isinstance(google_name, str)

    def test_all_configs_have_required_methods(self):
        """Test that all configs implement the required interface."""
        configs = [
            OllamaConfig(),
            GoogleGenAIConfig(api_key="test"),
        ]

        for config in configs:
            # All should have these methods
            assert hasattr(config, 'create_llm')
            assert hasattr(config, 'get_prompt_template')
            assert hasattr(config, 'get_display_name')

            # Test they return correct types
            assert isinstance(config.get_display_name(), str)
            template = config.get_prompt_template()

            # Verify security-specific variables
            assert 'context' in template.input_variables
            assert 'finding_type' in template.input_variables
            assert 'original_code' in template.input_variables

    def test_prompt_templates_match_between_providers(self):
        """Test that both providers use the same variable names."""
        ollama = LLMFactory.create_ollama()
        google = LLMFactory.create_google(api_key="test")

        ollama_vars = set(ollama.get_prompt_template().input_variables)
        google_vars = set(google.get_prompt_template().input_variables)

        # Both should have the same input variables
        assert ollama_vars == google_vars, "Input variables should match between providers"


class TestSecurityPromptContent:
    """Test security-specific prompt content."""

    def test_prompt_includes_json_format_instruction(self):
        """Test that prompts request JSON output."""
        configs = [
            OllamaConfig(),
            GoogleGenAIConfig(api_key="test"),
        ]

        for config in configs:
            template = config.get_prompt_template()
            template_lower = template.template.lower()

            assert "json" in template_lower, f"Prompt should request JSON format for {config.get_display_name()}"

    def test_prompt_includes_security_terminology(self):
        """Test that prompts include security-related terms."""
        configs = [
            OllamaConfig(),
            GoogleGenAIConfig(api_key="test"),
        ]

        security_terms = ["vulnerability", "security", "fix", "suggested_fix", "cwe"]

        for config in configs:
            template = config.get_prompt_template()
            template_lower = template.template.lower()

            # At least some security terms should be present
            found_terms = [term for term in security_terms if term in template_lower]
            assert len(found_terms) >= 2, f"Prompt should include security terminology for {config.get_display_name()}"

    def test_prompt_requests_confidence_level(self):
        """Test that prompts request confidence level in response."""
        configs = [
            OllamaConfig(),
            GoogleGenAIConfig(api_key="test"),
        ]

        for config in configs:
            template = config.get_prompt_template()
            template_lower = template.template.lower()

            assert "confidence" in template_lower, f"Prompt should request confidence level for {config.get_display_name()}"


@pytest.fixture
def mock_llm_config():
    """Fixture providing a mock LLM config for testing RemediationEngine."""
    config = Mock()

    mock_llm = Mock()
    config.create_llm.return_value = mock_llm

    from langchain_core.prompts import PromptTemplate
    config.get_prompt_template.return_value = PromptTemplate(
        template="""Context: {context}
Type: {finding_type}
Line: {line_number}
File: {file_path}
Severity: {severity}
CWE: {cwe_id}
Code: {original_code}
Fix:""",
        input_variables=["context", "finding_type", "line_number", "file_path",
                         "severity", "cwe_id", "original_code"]
    )

    config.get_display_name.return_value = "Mock LLM"

    return config


@pytest.fixture
def mock_vector_store():
    """Fixture providing a mock vector store."""
    mock_vs = Mock()
    mock_retriever = Mock()
    mock_vs.as_retriever.return_value = mock_retriever
    mock_vs._embedding_function = Mock()
    mock_vs._embedding_function.embed_documents = Mock(return_value=[[0.1] * 384])
    return mock_vs


@pytest.fixture
def sample_vulnerability():
    """Fixture providing a sample vulnerability finding."""
    return {
        'type': 'SQL Injection',
        'snippet': 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        'line_number': 42,
        'file_path': 'app/database.py',
        'severity': 'High',
        'cwe_id': 'CWE-89'
    }


@pytest.fixture
def sample_vulnerability_minimal():
    """Fixture providing a minimal vulnerability finding (only required fields)."""
    return {
        'type': 'XSS',
        'snippet': 'return render_template("index.html", user_input=request.args.get("q"))'
    }


if __name__ == "__main__":
    pytest.main([__file__, "-v"])