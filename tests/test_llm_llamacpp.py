import os

import pytest
from unittest.mock import Mock, patch
from pathlib import Path

from securefix.remediation.llm import LLMFactory, LLAMACPP_AVAILABLE

if LLAMACPP_AVAILABLE:
    from securefix.remediation.llm import (
        LlamaCPPConfig,
        check_llamacpp_available,
        validate_gguf_model,
        get_recommended_settings,
    )


@pytest.mark.skipif(not LLAMACPP_AVAILABLE, reason="llama-cpp-python not installed")
class TestLlamaCPPConfig:
    """Test LlamaCPP configuration when library is available."""

    def test_get_display_name(self, tmp_path):
        """Test display name formatting."""
        model_file = tmp_path / "test-model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        config = LlamaCPPConfig(model_path=str(model_file))
        display_name = config.get_display_name()

        assert isinstance(display_name, str)
        assert "llamacpp" in display_name.lower() or "test-model" in display_name.lower()

    def test_get_prompt_template(self, tmp_path):
        """Test prompt template generation."""
        model_file = tmp_path / "test-model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        config = LlamaCPPConfig(model_path=str(model_file))
        template = config.get_prompt_template()

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
        assert "vulnerability" in template.template.lower() or "security" in template.template.lower()

    @patch('langchain_community.llms.LlamaCpp')
    def test_create_llm_success(self, mock_llamacpp_class, tmp_path):
        """Test successful LLM creation."""
        model_file = tmp_path / "test-model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        config = LlamaCPPConfig(
            model_path=str(model_file),
            temperature=0.2,
            max_tokens=500,
            n_ctx=2048,
            n_threads=4,
            n_gpu_layers=0,
        )

        mock_llm = Mock()
        mock_llamacpp_class.return_value = mock_llm

        llm = config.create_llm()

        mock_llamacpp_class.assert_called_once()
        call_kwargs = mock_llamacpp_class.call_args[1]

        assert call_kwargs['model_path'] == str(model_file)
        assert call_kwargs['temperature'] == 0.2
        assert call_kwargs['max_tokens'] == 500
        assert call_kwargs['n_ctx'] == 2048
        assert call_kwargs['n_threads'] == 4
        assert call_kwargs['n_gpu_layers'] == 0
        assert llm == mock_llm

    def test_create_llm_file_not_found(self):
        """Test that create_llm raises error for non-existent file."""
        config = LlamaCPPConfig(model_path="/nonexistent/model.gguf")

        with pytest.raises(FileNotFoundError, match="Model file not found"):
            config.create_llm()

    @patch.dict(os.environ, {}, clear=True)  # Clear env vars for clean test
    def test_default_parameters(self, tmp_path):
        """Test that default parameters are set correctly."""
        model_file = tmp_path / "test-model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        config = LlamaCPPConfig(model_path=str(model_file))

        assert config.temperature == 0.1
        assert config.max_tokens == 600
        assert config.n_ctx == 2048
        assert config.n_threads is None  # Should be None by default
        assert config.n_gpu_layers == 0
        assert config.top_k == 40
        assert config.top_p == 0.9
        assert config.repeat_penalty == 1.1
        assert config.verbose is False


@pytest.mark.skipif(not LLAMACPP_AVAILABLE, reason="llama-cpp-python not installed")
class TestLlamaCPPUtilityFunctions:
    """Test LlamaCPP utility functions."""

    def test_check_llamacpp_available(self):
        """Test that check returns True when library is installed."""
        result = check_llamacpp_available()
        assert result is True

    def test_validate_gguf_model_success(self, tmp_path):
        """Test validating a valid GGUF file."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        is_valid, error_msg = validate_gguf_model(str(model_file))

        assert is_valid is True
        assert error_msg is None

    def test_validate_gguf_model_not_found(self):
        """Test validation with non-existent file."""
        is_valid, error_msg = validate_gguf_model("/nonexistent/model.gguf")

        assert is_valid is False
        assert "not found" in error_msg.lower()

    def test_validate_gguf_model_wrong_extension(self, tmp_path):
        """Test validation with wrong file extension."""
        model_file = tmp_path / "model.txt"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        is_valid, error_msg = validate_gguf_model(str(model_file))

        assert is_valid is False
        assert "extension" in error_msg.lower()

    def test_validate_gguf_model_too_small(self, tmp_path):
        """Test validation with file that's too small."""
        model_file = tmp_path / "model.gguf"
        model_file.write_bytes(b"x" * 1024)

        is_valid, error_msg = validate_gguf_model(str(model_file))

        assert is_valid is False
        assert "too small" in error_msg.lower()

    def test_validate_gguf_model_bin_extension(self, tmp_path):
        """Test that .bin extension is also accepted."""
        model_file = tmp_path / "model.bin"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        is_valid, error_msg = validate_gguf_model(str(model_file))

        assert is_valid is True

    def test_validate_gguf_model_directory(self, tmp_path):
        """Test validation fails for directory."""
        model_dir = tmp_path / "model.gguf"
        model_dir.mkdir()

        is_valid, error_msg = validate_gguf_model(str(model_dir))

        assert is_valid is False
        assert "not a file" in error_msg.lower()

    def test_get_recommended_settings_small_model(self):
        """Test recommended settings for small model (< 1GB)."""
        settings = get_recommended_settings(500)

        assert settings['n_ctx'] == 2048
        assert settings['n_threads'] == 4
        assert settings['max_tokens'] == 600
        assert 'n_gpu_layers' in settings

    def test_get_recommended_settings_medium_model(self):
        """Test recommended settings for medium model (1-4GB)."""
        settings = get_recommended_settings(3000)

        assert settings['n_ctx'] == 2048
        assert settings['n_threads'] == 6
        assert settings['max_tokens'] == 500

    def test_get_recommended_settings_large_model(self):
        """Test recommended settings for large model (> 4GB)."""
        settings = get_recommended_settings(8000)

        assert settings['n_ctx'] == 2048
        assert settings['n_threads'] == 8
        assert settings['max_tokens'] == 400


@pytest.mark.skipif(not LLAMACPP_AVAILABLE, reason="llama-cpp-python not installed")
class TestLLMFactoryLlamaCPP:
    """Test LLM factory methods for LlamaCPP."""

    def test_is_llamacpp_available(self):
        """Test that factory reports LlamaCPP as available."""
        result = LLMFactory.is_llamacpp_available()
        assert result is True

    def test_create_llamacpp(self, tmp_path):
        """Test creating LlamaCPP config via factory."""
        model_file = tmp_path / "test-model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        config = LLMFactory.create_llamacpp(
            model_path=str(model_file),
            temperature=0.3,
            n_threads=8,
        )

        assert isinstance(config, LlamaCPPConfig)
        assert config.model_path == str(model_file)
        assert config.temperature == 0.3
        assert config.n_threads == 8

    def test_create_from_mode_llamacpp(self, tmp_path):
        """Test creating LlamaCPP config via mode string."""
        model_file = tmp_path / "test-model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        config = LLMFactory.create_from_mode(
            mode="llamacpp",
            model_path=str(model_file)
        )

        assert isinstance(config, LlamaCPPConfig)
        assert config.model_path == str(model_file)

    def test_create_from_mode_llamacpp_without_path(self):
        """Test that llamacpp mode requires model_path."""
        with pytest.raises(ValueError, match="requires model_path"):
            LLMFactory.create_from_mode(mode="llamacpp")


@pytest.mark.skipif(LLAMACPP_AVAILABLE, reason="Test only runs when llama-cpp-python is NOT installed")
class TestLlamaCPPUnavailable:
    """Test behavior when llama-cpp-python is NOT installed."""

    def test_factory_raises_helpful_error(self):
        """Test that factory raises helpful error when LlamaCPP unavailable."""
        with pytest.raises(ValueError, match="llama-cpp-python") as exc_info:
            LLMFactory.create_llamacpp(model_path="test.gguf")

        error_msg = str(exc_info.value)
        assert "pip install" in error_msg

    def test_create_from_mode_helpful_error_message(self):
        """Test error message suggests installation method."""
        with pytest.raises(ValueError) as exc_info:
            LLMFactory.create_from_mode(
                mode="llamacpp",
                model_path="test.gguf"
            )

        error_msg = str(exc_info.value)
        assert "pip install" in error_msg
        assert "llama-cpp-python" in error_msg


@pytest.mark.skipif(not LLAMACPP_AVAILABLE, reason="llama-cpp-python not installed")
class TestLlamaCPPIntegration:
    """Integration tests for LlamaCPP configuration."""

    def test_config_has_required_interface(self, tmp_path):
        """Test that LlamaCPP config implements required interface."""
        model_file = tmp_path / "test-model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        config = LlamaCPPConfig(model_path=str(model_file))

        assert hasattr(config, 'create_llm')
        assert hasattr(config, 'get_prompt_template')
        assert hasattr(config, 'get_display_name')

        assert isinstance(config.get_display_name(), str)
        template = config.get_prompt_template()
        assert 'context' in template.input_variables

    def test_prompt_template_matches_other_providers(self, tmp_path):
        """Test that LlamaCPP uses same variables as other providers."""
        model_file = tmp_path / "test-model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        from securefix.remediation.llm import OllamaConfig, GoogleGenAIConfig

        llamacpp = LlamaCPPConfig(model_path=str(model_file))
        ollama = OllamaConfig()
        google = GoogleGenAIConfig(api_key="test")

        llamacpp_vars = set(llamacpp.get_prompt_template().input_variables)
        ollama_vars = set(ollama.get_prompt_template().input_variables)
        google_vars = set(google.get_prompt_template().input_variables)

        assert llamacpp_vars == ollama_vars == google_vars

    def test_all_providers_available(self, tmp_path):
        """Test creating configs for all available providers."""
        model_file = tmp_path / "test-model.gguf"
        model_file.write_bytes(b"x" * (15 * 1024 * 1024))

        configs = {
            'ollama': LLMFactory.create_ollama(),
            'google': LLMFactory.create_google(api_key="test"),
            'llamacpp': LLMFactory.create_llamacpp(model_path=str(model_file)),
        }

        for name, config in configs.items():
            assert hasattr(config, 'get_display_name')
            display_name = config.get_display_name()
            assert isinstance(display_name, str)
            assert len(display_name) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])