"""
Tests for corpus_builder.py

Covers:
- Security corpus loading from various file types (CSV, MD, YAML)
- Retry logic and error handling
- BM25 index building
- Vector store creation
- Progress tracking
"""
import os
import pytest
from unittest.mock import Mock, patch, MagicMock, call
from pathlib import Path
from langchain_core.documents import Document

from remediation.corpus_builder import (
    DocumentProcessor,
    LoadResult,
    ProgressEmbeddings,
    create_progress_embeddings
)


@pytest.fixture
def doc_processor(tmp_path, mock_embeddings):
    """Create DocumentProcessor with mocked embeddings"""
    with patch.object(DocumentProcessor, '_setup_embeddings', return_value=mock_embeddings):
        processor = DocumentProcessor(persist_directory=str(tmp_path / "chroma_db"))
    return processor


@pytest.fixture
def sample_security_documents():
    """Sample security corpus documents for testing"""
    return [
        Document(
            page_content="CWE-89: SQL Injection\n\nDescription: Improper neutralization of special elements",
            metadata={"source": "cwe.csv", "cwe_id": "CWE-89", "doc_type": "cwe"}
        ),
        Document(
            page_content="# Input Validation Cheat Sheet\n\nValidate all user input...",
            metadata={"source": "input_validation.md", "doc_type": "owasp_cheatsheet"}
        ),
        Document(
            page_content="Vulnerability ID: PYSEC-2024-001\n\nDetails: Authentication bypass...",
            metadata={"source": "advisory.yaml", "doc_type": "pypa_advisory"}
        ),
    ]


class TestProgressEmbeddings:
    """Test progress tracking wrapper"""

    def test_embed_documents_updates_progress(self, mock_embeddings):
        """Test that embedding documents updates progress bar"""
        wrapper = ProgressEmbeddings(mock_embeddings, total_chunks=10)

        texts = ["text1", "text2", "text3"]
        result = wrapper.embed_documents(texts)

        assert wrapper.embedded_count == 3
        # Check that result is a list (the actual value comes from mock)
        assert isinstance(result, list)
        mock_embeddings.embed_documents.assert_called_once_with(texts)
        wrapper.close()

    def test_embed_query_passthrough(self, mock_embeddings):
        """Test that query embedding passes through without tracking"""
        wrapper = ProgressEmbeddings(mock_embeddings, total_chunks=10)

        result = wrapper.embed_query("test query")

        # Check that result is a list (the actual value comes from mock)
        assert isinstance(result, list)
        assert wrapper.embedded_count == 0  # Query embedding shouldn't increment
        mock_embeddings.embed_query.assert_called_once_with("test query")
        wrapper.close()

    def test_context_manager(self, mock_embeddings):
        """Test progress embeddings context manager"""
        with create_progress_embeddings(mock_embeddings, 5) as wrapper:
            assert isinstance(wrapper, ProgressEmbeddings)
            wrapper.embed_documents(["test"])

        # Progress bar should be closed after context exits
        assert wrapper.pbar.n == 1  # One update was made


class TestSecurityCorpusLoading:
    """Test security corpus loading functionality"""

    def test_load_documents_empty_folder(self, doc_processor, tmp_path):
        """Test loading from non-existent folder"""
        result = doc_processor.load_documents(str(tmp_path / "nonexistent"))

        assert isinstance(result, LoadResult)
        assert result.loaded_documents == []
        assert result.failed_files == []

    def test_load_documents_no_supported_files(self, doc_processor, tmp_path):
        """Test loading from folder with no supported files"""
        docs_folder = tmp_path / "corpus"
        docs_folder.mkdir()

        # Create unsupported file
        (docs_folder / "test.xyz").write_text("unsupported")

        result = doc_processor.load_documents(str(docs_folder))

        assert result.loaded_documents == []
        assert result.failed_files == []

    def test_load_single_csv_file(self, doc_processor, tmp_path):
        """Test loading a single CWE CSV file"""
        corpus_folder = tmp_path / "corpus"
        corpus_folder.mkdir()
        csv_file = corpus_folder / "cwe.csv"
        csv_content = """CWE-ID,Name,Description,Extended Description,Potential Mitigations
89,SQL Injection,Improper input validation,Extended details,Use parameterized queries"""
        csv_file.write_text(csv_content)

        result = doc_processor.load_documents(str(corpus_folder))

        assert len(result.loaded_documents) == 1
        assert "CWE-89" in result.loaded_documents[0].page_content
        assert result.loaded_documents[0].metadata['doc_type'] == 'cwe'
        assert len(result.failed_files) == 0

    def test_load_single_markdown_file(self, doc_processor, tmp_path):
        """Test loading a single OWASP markdown file"""
        corpus_folder = tmp_path / "corpus"
        corpus_folder.mkdir()
        md_file = corpus_folder / "cheatsheet.md"
        md_file.write_text("# Security Cheat Sheet\n\nBest practices...")

        result = doc_processor.load_documents(str(corpus_folder))

        assert len(result.loaded_documents) == 1
        assert result.loaded_documents[0].metadata['doc_type'] == 'owasp_cheatsheet'
        assert len(result.failed_files) == 0

    def test_load_single_yaml_file(self, doc_processor, tmp_path):
        """Test loading a single PyPA advisory YAML file"""
        corpus_folder = tmp_path / "corpus"
        corpus_folder.mkdir()
        yaml_file = corpus_folder / "advisory.yaml"
        yaml_content = """id: PYSEC-2024-001
details: Security vulnerability description
affected:
  - package:
      name: test-package
      ecosystem: PyPI
"""
        yaml_file.write_text(yaml_content)

        result = doc_processor.load_documents(str(corpus_folder))

        assert len(result.loaded_documents) == 1
        assert result.loaded_documents[0].metadata['doc_type'] == 'pypa_advisory'
        assert len(result.failed_files) == 0

    def test_retry_logic_on_failure(self, doc_processor, tmp_path):
        """Test that retry logic works on transient failures"""
        corpus_folder = tmp_path / "corpus"
        corpus_folder.mkdir()
        csv_file = corpus_folder / "test.csv"
        csv_file.write_text("CWE-ID,Name\n79,XSS")

        with patch.object(doc_processor, '_load_cwe_csv') as mock_load:
            # Fail twice, then succeed
            mock_load.side_effect = [
                Exception("Transient error 1"),
                Exception("Transient error 2"),
                [Document(page_content="Success", metadata={"doc_type": "cwe"})]
            ]

            result = doc_processor.load_documents(str(corpus_folder), retries=2)

            assert len(result.loaded_documents) == 1
            assert len(result.failed_files) == 0
            assert mock_load.call_count == 3

    def test_retry_exhaustion(self, doc_processor, tmp_path):
        """Test that files are marked as failed after all retries"""
        corpus_folder = tmp_path / "corpus"
        corpus_folder.mkdir()
        csv_file = corpus_folder / "test.csv"
        csv_file.write_text("CWE-ID,Name\n79,XSS")

        with patch.object(doc_processor, '_load_cwe_csv') as mock_load:
            mock_load.side_effect = Exception("Persistent error")

            result = doc_processor.load_documents(str(corpus_folder), retries=2)

            assert len(result.loaded_documents) == 0
            assert len(result.failed_files) == 1
            assert "test.csv" in result.failed_files[0]['path']
            assert "Persistent error" in result.failed_files[0]['error']

    def test_parallel_loading_multiple_files(self, doc_processor, tmp_path):
        """Test parallel loading of multiple security corpus files"""
        corpus_folder = tmp_path / "corpus"
        corpus_folder.mkdir()

        # Create multiple corpus files
        (corpus_folder / "cwe.csv").write_text("CWE-ID,Name\n89,SQLi")
        (corpus_folder / "cheatsheet.md").write_text("# Security Guide")
        (corpus_folder / "advisory.yaml").write_text("id: PYSEC-001\ndetails: Test")

        result = doc_processor.load_documents(str(corpus_folder))

        assert len(result.loaded_documents) == 3
        assert len(result.failed_files) == 0


class TestDocumentProcessing:
    """Test document processing pipeline"""

    def test_split_documents(self, doc_processor, sample_security_documents):
        """Test document splitting"""
        # Create long document
        long_doc = Document(
            page_content="vulnerability " * 1000,  # Long enough to be split
            metadata={"source": "long.csv", "doc_type": "cwe"}
        )

        chunks = doc_processor._split_documents_batch([long_doc])

        assert len(chunks) > 1
        assert all(isinstance(chunk, Document) for chunk in chunks)

    def test_build_bm25_index(self, doc_processor, sample_security_documents):
        """Test BM25 index building"""
        bm25_index, bm25_chunks = doc_processor._build_bm25_index(sample_security_documents)

        assert bm25_index is not None
        assert len(bm25_chunks) == len(sample_security_documents)
        assert bm25_chunks == sample_security_documents

    @patch.object(DocumentProcessor, 'load_documents')
    @patch.object(DocumentProcessor, '_create_vectorstore_batched')
    def test_process_documents_success(self, mock_create_vs, mock_load,
                                       doc_processor, sample_security_documents):
        """Test successful document processing pipeline"""
        mock_load.return_value = LoadResult(
            loaded_documents=sample_security_documents,
            failed_files=[]
        )
        mock_vs = Mock()
        mock_create_vs.return_value = mock_vs

        result = doc_processor.process_documents("remediation/corpus")

        assert result is not None
        vector_store, bm25_index, bm25_chunks = result
        assert vector_store == mock_vs
        assert bm25_index is not None
        assert len(bm25_chunks) > 0

    @patch.object(DocumentProcessor, 'load_documents')
    def test_process_documents_no_documents_loaded(self, mock_load, doc_processor):
        """Test processing when no documents are loaded"""
        mock_load.return_value = LoadResult(
            loaded_documents=[],
            failed_files=[{"path": "test.csv", "error": "Failed to load"}]
        )

        result = doc_processor.process_documents("remediation/corpus")

        assert result is None

    @patch.object(DocumentProcessor, 'load_documents')
    @patch.object(DocumentProcessor, '_create_vectorstore_batched')
    def test_process_documents_with_failed_files(self, mock_create_vs, mock_load,
                                                 doc_processor, sample_security_documents):
        """Test processing with some failed files"""
        mock_load.return_value = LoadResult(
            loaded_documents=sample_security_documents,
            failed_files=[{"path": "bad.yaml", "error": "Corrupted"}]
        )
        mock_vs = Mock()
        mock_create_vs.return_value = mock_vs

        result = doc_processor.process_documents("remediation/corpus")

        assert result is not None  # Should still succeed with partial documents


class TestVectorStore:
    """Test vector store operations"""

    @patch('remediation.corpus_builder.Chroma')
    def test_create_vectorstore(self, mock_chroma, doc_processor, sample_security_documents):
        """Test vector store creation"""
        mock_vs = Mock()
        mock_chroma.from_documents.return_value = mock_vs

        vs = doc_processor._create_vectorstore_batched(sample_security_documents)

        assert vs == mock_vs
        mock_chroma.from_documents.assert_called_once()

    @patch('remediation.corpus_builder.Chroma')
    def test_load_existing_vectorstore_success(self, mock_chroma, doc_processor):
        """Test loading existing vector store"""
        mock_vs = Mock()
        mock_vs.get.return_value = {
            "documents": ["doc1", "doc2"],
            "metadatas": [{"source": "1"}, {"source": "2"}]
        }
        mock_chroma.return_value = mock_vs

        # Create the persist directory
        os.makedirs(doc_processor.persist_directory, exist_ok=True)

        vs, bm25_index, bm25_chunks = doc_processor.load_existing_vectorstore()

        assert vs == mock_vs
        assert bm25_index is not None
        assert len(bm25_chunks) == 2

    def test_load_existing_vectorstore_not_found(self, doc_processor):
        """Test loading when vector store doesn't exist"""
        vs, bm25_index, bm25_chunks = doc_processor.load_existing_vectorstore()

        assert vs is None
        assert bm25_index is None
        assert bm25_chunks is None

    @patch('remediation.corpus_builder.Chroma')
    def test_load_existing_vectorstore_empty(self, mock_chroma, doc_processor):
        """Test loading empty vector store"""
        mock_vs = Mock()
        mock_vs.get.return_value = {
            "documents": [],
            "metadatas": []
        }
        mock_chroma.return_value = mock_vs

        os.makedirs(doc_processor.persist_directory, exist_ok=True)

        vs, bm25_index, bm25_chunks = doc_processor.load_existing_vectorstore()

        assert vs == mock_vs
        assert bm25_index is None
        assert bm25_chunks is None


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_supported_extensions(self, doc_processor):
        """Test that supported extensions are properly defined"""
        assert '.csv' in doc_processor.supported_extensions
        assert '.md' in doc_processor.supported_extensions
        assert '.yaml' in doc_processor.supported_extensions
        assert '.yml' in doc_processor.supported_extensions

    def test_empty_document_content(self, doc_processor):
        """Test handling of empty document content"""
        empty_docs = [Document(page_content="", metadata={"source": "empty.csv", "doc_type": "cwe"})]

        chunks = doc_processor._split_documents_batch(empty_docs)

        # Should handle empty content gracefully
        assert isinstance(chunks, list)

    def test_very_small_chunks(self, doc_processor):
        """Test processing very small documents"""
        small_doc = Document(
            page_content="CWE-89",
            metadata={"source": "small.csv", "doc_type": "cwe"}
        )

        chunks = doc_processor._split_documents_batch([small_doc])

        assert len(chunks) >= 1
        assert chunks[0].page_content == "CWE-89"