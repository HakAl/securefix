"""
Tests for remediation_engine.py

Covers:
- Vulnerability fix generation
- Caching behavior (hits and misses)
- Error handling and formatting
- Integration with LLM and retriever
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from langchain_core.documents import Document

from remediation.remediation_engine import RemediationEngine, RemediationEngineError


# Mock NLTK at module import time if it doesn't exist
import remediation.remediation_engine as remediation_engine
if not hasattr(remediation_engine, 'word_tokenize'):
    remediation_engine.word_tokenize = lambda x: x.split()


@pytest.fixture
def remediation_engine_fixture(mock_document_store, mock_llm_config):
    """Create RemediationEngine with mocked dependencies"""
    with patch.object(remediation_engine, 'STOP_WORDS', {'what', 'is', 'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for'}):
        return RemediationEngine(
            document_store=mock_document_store,
            llm_config=mock_llm_config,
            enable_cache=True,
            cache_similarity_threshold=0.85,
            cache_max_size=100
        )


@pytest.fixture
def remediation_engine_no_cache(mock_document_store, mock_llm_config):
    """Create RemediationEngine without caching"""
    return RemediationEngine(
        document_store=mock_document_store,
        llm_config=mock_llm_config,
        enable_cache=False
    )


@pytest.fixture
def sample_vulnerability_finding():
    """Sample vulnerability finding for testing"""
    return {
        "type": "SQL Injection",
        "snippet": "query = 'SELECT * FROM users WHERE id = ' + user_id",
        "line_number": 42,
        "file_path": "app/database.py",
        "severity": "High",
        "cwe_id": "CWE-89"
    }


@pytest.fixture
def sample_security_source_docs():
    """Sample source documents for testing"""
    return [
        Document(
            page_content="CWE-89: SQL Injection prevention using parameterized queries",
            metadata={"source": "cwe.csv", "cwe_id": "CWE-89"}
        ),
        Document(
            page_content="Use prepared statements to prevent SQL injection",
            metadata={"source": "owasp.md", "doc_type": "owasp_cheatsheet"}
        ),
    ]


class TestRemediationEngineInitialization:
    """Test RemediationEngine initialization"""

    def test_init_with_cache_enabled(self, mock_document_store, mock_llm_config):
        """Test initialization with cache enabled"""
        engine = RemediationEngine(
            document_store=mock_document_store,
            llm_config=mock_llm_config,
            enable_cache=True
        )

        assert engine.enable_cache is True
        assert engine.cache is not None

    def test_init_with_cache_disabled(self, mock_document_store, mock_llm_config):
        """Test initialization with cache disabled"""
        engine = RemediationEngine(
            document_store=mock_document_store,
            llm_config=mock_llm_config,
            enable_cache=False
        )

        assert engine.enable_cache is False
        assert engine.cache is None

    def test_init_sets_llm_and_prompt(self, remediation_engine_fixture, mock_llm_config):
        """Test that LLM and prompt are set correctly"""
        assert remediation_engine_fixture.llm is not None
        assert remediation_engine_fixture.prompt is not None
        mock_llm_config.create_llm.assert_called_once()
        mock_llm_config.get_prompt_template.assert_called_once()


class TestFixGeneration:
    """Test vulnerability fix generation"""

    def test_generate_fix_basic(self, remediation_engine_fixture, sample_vulnerability_finding, sample_security_source_docs):
        """Test basic fix generation"""
        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_result = {
                "result": '{"suggested_fix": "query = db.execute_query(?, [user_id])", "explanation": "Use parameterized queries", "confidence": "High", "cwe_id": "CWE-89"}',
                "source_documents": sample_security_source_docs
            }
            mock_chain.invoke.return_value = mock_result
            mock_qa_class.from_chain_type.return_value = mock_chain

            result = remediation_engine_fixture.generate_fix(sample_vulnerability_finding)

            assert "answer" in result
            assert "source_documents" in result
            assert len(result["source_documents"]) == 2

    def test_generate_fix_without_optional_fields(self, remediation_engine_fixture):
        """Test fix generation with minimal vulnerability info"""
        minimal_finding = {
            "type": "SQL Injection",
            "snippet": "SELECT * FROM users"
        }

        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_result = {
                "result": '{"suggested_fix": "fixed_code", "explanation": "test"}',
                "source_documents": []
            }
            mock_chain.invoke.return_value = mock_result
            mock_qa_class.from_chain_type.return_value = mock_chain

            result = remediation_engine_fixture.generate_fix(minimal_finding)

            assert "answer" in result
            # Should handle missing fields gracefully

    def test_generate_fix_creates_chain_lazily(self, remediation_engine_fixture, sample_vulnerability_finding):
        """Test that chain is created lazily on first use"""
        assert remediation_engine_fixture._chain is None

        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_chain.invoke.return_value = {"result": "{}", "source_documents": []}
            mock_qa_class.from_chain_type.return_value = mock_chain

            remediation_engine_fixture.generate_fix(sample_vulnerability_finding)

            assert remediation_engine_fixture._chain is not None

    def test_generate_fix_reuses_chain(self, remediation_engine_fixture, sample_vulnerability_finding):
        """Test that chain is reused for multiple calls"""
        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_chain.invoke.return_value = {"result": "{}", "source_documents": []}
            mock_qa_class.from_chain_type.return_value = mock_chain

            remediation_engine_fixture.generate_fix(sample_vulnerability_finding)
            remediation_engine_fixture.generate_fix(sample_vulnerability_finding)

            # from_chain_type should only be called once
            assert mock_qa_class.from_chain_type.call_count == 1


class TestCaching:
    """Test semantic cache functionality"""

    def test_cache_miss_on_first_call(self, remediation_engine_fixture, sample_vulnerability_finding, sample_security_source_docs):
        """Test cache miss on first vulnerability"""
        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_result = {
                "result": '{"suggested_fix": "fixed"}',
                "source_documents": sample_security_source_docs
            }
            mock_chain.invoke.return_value = mock_result
            mock_qa_class.from_chain_type.return_value = mock_chain

            result = remediation_engine_fixture.generate_fix(sample_vulnerability_finding)

            # Should call the chain (cache miss)
            mock_chain.invoke.assert_called_once()

    def test_cache_hit_on_similar_vulnerability(self, remediation_engine_fixture, sample_vulnerability_finding, sample_security_source_docs):
        """Test cache hit on similar vulnerability"""
        cached_result = {
            "answer": '{"suggested_fix": "cached_fix"}',
            "source_documents": sample_security_source_docs
        }

        with patch.object(remediation_engine_fixture.cache, 'get', return_value=cached_result):
            result = remediation_engine_fixture.generate_fix(sample_vulnerability_finding)

            assert result == cached_result

    def test_cache_disabled(self, remediation_engine_no_cache, sample_vulnerability_finding, sample_security_source_docs):
        """Test that caching can be disabled"""
        assert remediation_engine_no_cache.cache is None

        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_result = {
                "result": "{}",
                "source_documents": sample_security_source_docs
            }
            mock_chain.invoke.return_value = mock_result
            mock_qa_class.from_chain_type.return_value = mock_chain

            remediation_engine_no_cache.generate_fix(sample_vulnerability_finding)
            remediation_engine_no_cache.generate_fix(sample_vulnerability_finding)

            # Should call chain twice since cache is disabled
            assert mock_chain.invoke.call_count == 2

    def test_clear_cache(self, remediation_engine_fixture):
        """Test cache clearing"""
        if remediation_engine_fixture.cache:
            remediation_engine_fixture.cache.cache = {"test": "data"}

            remediation_engine_fixture.clear_cache()

            assert len(remediation_engine_fixture.cache.cache) == 0

    def test_get_cache_stats(self, remediation_engine_fixture):
        """Test cache statistics"""
        stats = remediation_engine_fixture.get_cache_stats()

        assert stats["cache_enabled"] is True
        assert stats["cache_size"] == 0
        assert stats["max_size"] == 100
        assert stats["similarity_threshold"] == 0.85

    def test_get_cache_stats_disabled(self, remediation_engine_no_cache):
        """Test cache statistics when cache is disabled"""
        stats = remediation_engine_no_cache.get_cache_stats()

        assert stats["cache_enabled"] is False


class TestErrorHandling:
    """Test error handling and error messages"""

    def test_llm_error_with_ollama_hints(self, remediation_engine_fixture, sample_vulnerability_finding):
        """Test error message includes Ollama troubleshooting hints"""
        with patch.object(remediation_engine_fixture.llm_config, 'get_display_name', return_value="Ollama Model"):
            with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
                mock_chain = Mock()
                mock_chain.invoke.side_effect = Exception("Connection refused")
                mock_qa_class.from_chain_type.return_value = mock_chain

                with pytest.raises(RemediationEngineError) as exc_info:
                    remediation_engine_fixture.generate_fix(sample_vulnerability_finding)

                error_msg = str(exc_info.value)
                assert "Ollama" in error_msg
                assert "troubleshooting" in error_msg.lower()

    def test_llm_error_with_google_hints(self, remediation_engine_fixture, sample_vulnerability_finding):
        """Test error message includes Google API hints"""
        with patch.object(remediation_engine_fixture.llm_config, 'get_display_name', return_value="Google Gemini"):
            with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
                mock_chain = Mock()
                mock_chain.invoke.side_effect = Exception("API key invalid")
                mock_qa_class.from_chain_type.return_value = mock_chain

                with pytest.raises(RemediationEngineError) as exc_info:
                    remediation_engine_fixture.generate_fix(sample_vulnerability_finding)

                error_msg = str(exc_info.value)
                assert "Google" in error_msg or "Gemini" in error_msg
                assert "API key" in error_msg

    def test_generic_error_handling(self, remediation_engine_fixture, sample_vulnerability_finding):
        """Test generic error handling"""
        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_chain.invoke.side_effect = ValueError("Generic error")
            mock_qa_class.from_chain_type.return_value = mock_chain

            with pytest.raises(RemediationEngineError) as exc_info:
                remediation_engine_fixture.generate_fix(sample_vulnerability_finding)

            assert "Generic error" in str(exc_info.value)

    def test_remediation_engine_error_passthrough(self, remediation_engine_fixture, sample_vulnerability_finding):
        """Test that RemediationEngineError is passed through without wrapping"""
        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            original_error = RemediationEngineError("Custom error")
            mock_chain = Mock()
            mock_chain.invoke.side_effect = original_error
            mock_qa_class.from_chain_type.return_value = mock_chain

            with pytest.raises(RemediationEngineError) as exc_info:
                remediation_engine_fixture.generate_fix(sample_vulnerability_finding)

            # Should be the same error, not wrapped
            assert str(exc_info.value) == "Custom error"


class TestLLMInfo:
    """Test LLM information retrieval"""

    def test_get_llm_info(self, remediation_engine_fixture, mock_llm_config):
        """Test getting LLM display information"""
        mock_llm_config.get_display_name.return_value = "Test Model v1.0"

        info = remediation_engine_fixture.get_llm_info()

        assert info == "Test Model v1.0"


class TestPromptVariables:
    """Test prompt variable extraction"""

    def test_prompt_variables_extraction(self, remediation_engine_fixture, sample_vulnerability_finding):
        """Test that vulnerability finding is properly converted to prompt variables"""
        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_chain.invoke.return_value = {"result": "{}", "source_documents": []}
            mock_qa_class.from_chain_type.return_value = mock_chain

            remediation_engine_fixture.generate_fix(sample_vulnerability_finding)

            # Check that invoke was called with proper prompt variables
            call_args = mock_chain.invoke.call_args[0][0]
            assert "query" in call_args
            query_vars = call_args["query"]

            assert query_vars["finding_type"] == "SQL Injection"
            assert query_vars["line_number"] == 42
            assert query_vars["file_path"] == "app/database.py"
            assert query_vars["severity"] == "High"
            assert query_vars["cwe_id"] == "CWE-89"
            assert "user_id" in query_vars["original_code"]

    def test_prompt_variables_with_defaults(self, remediation_engine_fixture):
        """Test prompt variables use defaults for missing fields"""
        minimal_finding = {
            "type": "SQL Injection",
            "snippet": "SELECT * FROM users"
        }

        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_chain.invoke.return_value = {"result": "{}", "source_documents": []}
            mock_qa_class.from_chain_type.return_value = mock_chain

            remediation_engine_fixture.generate_fix(minimal_finding)

            call_args = mock_chain.invoke.call_args[0][0]
            query_vars = call_args["query"]

            # Check defaults are used
            assert query_vars["line_number"] == "Unknown"
            assert query_vars["file_path"] == "Unknown"
            assert query_vars["severity"] == "Medium"
            assert query_vars["cwe_id"] == ""


class TestIntegration:
    """Integration tests for complete workflows"""

    def test_complete_fix_workflow(self, remediation_engine_no_cache, sample_vulnerability_finding, sample_security_source_docs):
        """Test complete fix generation workflow"""
        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_result = {
                "result": '{"suggested_fix": "fixed_code", "explanation": "Use parameterized queries", "confidence": "High", "cwe_id": "CWE-89"}',
                "source_documents": sample_security_source_docs
            }
            mock_chain.invoke.return_value = mock_result
            mock_qa_class.from_chain_type.return_value = mock_chain

            result = remediation_engine_no_cache.generate_fix(sample_vulnerability_finding)

            assert "answer" in result
            assert "source_documents" in result
            assert len(result["source_documents"]) == 2
            # Verify source documents contain security content
            assert any("CWE" in doc.page_content for doc in result["source_documents"])

    def test_multiple_fix_generations(self, remediation_engine_no_cache, sample_vulnerability_finding):
        """Test multiple fix generations"""
        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_chain.invoke.return_value = {"result": "{}", "source_documents": []}
            mock_qa_class.from_chain_type.return_value = mock_chain

            # Generate multiple fixes
            for i in range(3):
                finding = sample_vulnerability_finding.copy()
                finding["line_number"] = 40 + i
                remediation_engine_no_cache.generate_fix(finding)

            # Chain should be reused
            assert mock_chain.invoke.call_count == 3


class TestTokenStreamCallbackHandler:
    """Test the streaming callback handler"""

    def test_callback_handler_calls_function(self):
        """Test that callback handler invokes the provided function"""
        from remediation.remediation_engine import TokenStreamCallbackHandler

        tokens_received = []

        def callback(token):
            tokens_received.append(token)

        handler = TokenStreamCallbackHandler(callback)

        handler.on_llm_new_token("Fixed")
        handler.on_llm_new_token(" ")
        handler.on_llm_new_token("code")

        assert tokens_received == ["Fixed", " ", "code"]

    def test_callback_handler_with_kwargs(self):
        """Test that callback handler handles additional kwargs"""
        from remediation.remediation_engine import TokenStreamCallbackHandler

        tokens_received = []

        def callback(token):
            tokens_received.append(token)

        handler = TokenStreamCallbackHandler(callback)

        # Should handle extra kwargs without error
        handler.on_llm_new_token("Test", chunk=None, run_id="123")

        assert tokens_received == ["Test"]


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_empty_vulnerability_snippet(self, remediation_engine_fixture):
        """Test handling of empty code snippet"""
        finding = {
            "type": "SQL Injection",
            "snippet": "",
            "line_number": 42
        }

        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_chain.invoke.return_value = {"result": "{}", "source_documents": []}
            mock_qa_class.from_chain_type.return_value = mock_chain

            result = remediation_engine_fixture.generate_fix(finding)

            # Should handle empty snippet
            assert "answer" in result

    def test_very_long_code_snippet(self, remediation_engine_fixture):
        """Test handling of very long code snippets"""
        finding = {
            "type": "SQL Injection",
            "snippet": "SELECT * FROM users WHERE " * 1000,  # Very long
            "line_number": 42
        }

        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_chain.invoke.return_value = {"result": "{}", "source_documents": []}
            mock_qa_class.from_chain_type.return_value = mock_chain

            result = remediation_engine_fixture.generate_fix(finding)

            assert "answer" in result

    def test_special_characters_in_code(self, remediation_engine_fixture):
        """Test handling of special characters in code"""
        finding = {
            "type": "SQL Injection",
            "snippet": "query = 'SELECT * FROM users WHERE name = \\'' + user_input + '\\'';",
            "line_number": 42
        }

        with patch.object(remediation_engine, 'RetrievalQA') as mock_qa_class:
            mock_chain = Mock()
            mock_chain.invoke.return_value = {"result": "{}", "source_documents": []}
            mock_qa_class.from_chain_type.return_value = mock_chain

            result = remediation_engine_fixture.generate_fix(finding)

            assert "answer" in result