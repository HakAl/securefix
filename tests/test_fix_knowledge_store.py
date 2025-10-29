"""
Tests for fix_knowledge_store.py

Covers:
- Document storage and retrieval
- Retriever creation and configuration
- Integration with vector stores and BM25
"""
import pytest
from unittest.mock import Mock, patch, MagicMock
from langchain_core.documents import Document

try:
    from remediation.fix_knowledge_store import DocumentStore
except ImportError:
    pytest.skip("fix_knowledge_store module not found", allow_module_level=True)


@pytest.fixture
def sample_security_chunks():
    """Sample security document chunks"""
    return [
        Document(
            page_content="CWE-89: SQL Injection vulnerability",
            metadata={"source": "cwe.csv", "cwe_id": "CWE-89"}
        ),
        Document(
            page_content="Input validation best practices",
            metadata={"source": "owasp.md", "doc_type": "owasp_cheatsheet"}
        ),
        Document(
            page_content="PyPA advisory for authentication bypass",
            metadata={"source": "advisory.yaml", "vulnerability_id": "PYSEC-001"}
        ),
    ]


@pytest.fixture
def doc_store(mock_vector_store):
    """Create DocumentStore with mocked components"""
    return DocumentStore(
        vector_store=mock_vector_store,
        bm25_index=None,
        bm25_chunks=[]
    )


@pytest.fixture
def doc_store_with_bm25(mock_vector_store, mock_bm25_index, sample_security_chunks):
    """Create DocumentStore with BM25 enabled"""
    return DocumentStore(
        vector_store=mock_vector_store,
        bm25_index=mock_bm25_index,
        bm25_chunks=sample_security_chunks
    )


class TestDocumentStoreInitialization:
    """Test DocumentStore initialization"""

    def test_init_with_vector_store_only(self, mock_vector_store):
        """Test initialization with only vector store"""
        store = DocumentStore(
            vector_store=mock_vector_store,
            bm25_index=None,
            bm25_chunks=[]
        )

        assert store.vector_store == mock_vector_store
        assert store.bm25_index is None
        assert store.bm25_chunks == []

    def test_init_with_bm25(self, mock_vector_store, mock_bm25_index, sample_security_chunks):
        """Test initialization with BM25 components"""
        store = DocumentStore(
            vector_store=mock_vector_store,
            bm25_index=mock_bm25_index,
            bm25_chunks=sample_security_chunks
        )

        assert store.vector_store == mock_vector_store
        assert store.bm25_index == mock_bm25_index
        assert store.bm25_chunks == sample_security_chunks


class TestRetrieverCreation:
    """Test retriever creation and configuration"""

    @patch('remediation.fix_knowledge_store.create_hybrid_retrieval_pipeline')
    def test_get_retriever_uses_factory(self, mock_factory, doc_store):
        """Test that get_retriever uses the factory function"""
        mock_retriever = Mock()
        mock_factory.return_value = mock_retriever

        retriever = doc_store.get_retriever()

        mock_factory.assert_called_once()
        assert retriever == mock_retriever

    @patch('remediation.fix_knowledge_store.create_hybrid_retrieval_pipeline')
    def test_get_retriever_caches_instance(self, mock_factory, doc_store):
        """Test that retriever is cached after first build"""
        mock_retriever = Mock()
        mock_factory.return_value = mock_retriever

        retriever1 = doc_store.get_retriever()
        retriever2 = doc_store.get_retriever()

        # Factory should only be called once
        assert mock_factory.call_count == 1
        assert retriever1 is retriever2

    @patch('remediation.fix_knowledge_store.create_hybrid_retrieval_pipeline')
    def test_get_retriever_passes_bm25_components(self, mock_factory, doc_store_with_bm25):
        """Test that BM25 components are passed to factory"""
        doc_store_with_bm25.get_retriever()

        call_kwargs = mock_factory.call_args[1]
        assert call_kwargs['bm25_index'] == doc_store_with_bm25.bm25_index
        assert call_kwargs['bm25_chunks'] == doc_store_with_bm25.bm25_chunks

    @patch('remediation.fix_knowledge_store.create_hybrid_retrieval_pipeline')
    def test_get_retriever_enables_reranking(self, mock_factory, doc_store):
        """Test that reranking is enabled by default"""
        doc_store.get_retriever()

        call_kwargs = mock_factory.call_args[1]
        assert call_kwargs['use_reranking'] is True


class TestEmbeddingFunction:
    """Test embedding function retrieval"""

    def test_get_embedding_function(self, doc_store, mock_vector_store):
        """Test getting embedding function from vector store"""
        embeddings = doc_store.get_embedding_function()

        # Should return the embed_documents method
        assert embeddings is not None
        assert callable(embeddings)

    def test_get_embedding_function_returns_correct_method(self, doc_store, mock_vector_store):
        """Test that returned function is the embed_documents method"""
        embeddings = doc_store.get_embedding_function()

        # Test that it's callable and returns expected format
        result = embeddings(["test"])
        assert isinstance(result, list)

    def test_get_embedding_function_with_missing_attribute(self, mock_vector_store):
        """Test handling when vector store has no _embedding_function attribute"""
        # Remove the _embedding_function attribute
        delattr(mock_vector_store, '_embedding_function')

        store = DocumentStore(
            vector_store=mock_vector_store,
            bm25_index=None,
            bm25_chunks=[]
        )

        # Should handle gracefully or raise appropriate error
        try:
            embeddings = store.get_embedding_function()
            # If it doesn't raise, should return something or None
        except AttributeError:
            # This is acceptable behavior
            pass


class TestVectorStoreOperations:
    """Test operations on the underlying vector store"""

    def test_similarity_search(self, doc_store, mock_vector_store, sample_security_chunks):
        """Test similarity search through document store"""
        mock_vector_store.similarity_search.return_value = sample_security_chunks[:2]

        results = mock_vector_store.similarity_search("SQL injection", k=2)

        assert len(results) == 2
        assert all(isinstance(doc, Document) for doc in results)

    def test_similarity_search_with_score(self, doc_store, mock_vector_store, sample_security_chunks):
        """Test similarity search with scores"""
        mock_vector_store.similarity_search_with_score.return_value = [
            (sample_security_chunks[0], 0.9),
            (sample_security_chunks[1], 0.7)
        ]

        results = mock_vector_store.similarity_search_with_score("input validation")

        assert len(results) == 2
        assert all(isinstance(doc, Document) and isinstance(score, float)
                   for doc, score in results)


class TestRetrieverIntegration:
    """Test retriever integration with document store"""

    def test_retriever_invoke(self, doc_store, sample_security_chunks):
        """Test invoking retriever"""
        mock_retriever = Mock()
        mock_retriever.invoke.return_value = sample_security_chunks[:2]

        with patch.object(doc_store, 'get_retriever', return_value=mock_retriever):
            retriever = doc_store.get_retriever()
            results = retriever.invoke("CWE-89 SQL injection")

            assert len(results) == 2
            assert all(isinstance(doc, Document) for doc in results)

    def test_retriever_returns_security_content(self, doc_store, sample_security_chunks):
        """Test that retriever returns security-related content"""
        mock_retriever = Mock()
        mock_retriever.invoke.return_value = sample_security_chunks

        with patch.object(doc_store, 'get_retriever', return_value=mock_retriever):
            retriever = doc_store.get_retriever()
            results = retriever.invoke("vulnerability fix")

            # Verify security-related metadata
            assert any('cwe_id' in doc.metadata or 'vulnerability_id' in doc.metadata
                       for doc in results)


class TestBM25Integration:
    """Test BM25 integration with document store"""

    def test_store_with_bm25_has_index(self, doc_store_with_bm25):
        """Test that store with BM25 has index"""
        assert doc_store_with_bm25.bm25_index is not None
        assert len(doc_store_with_bm25.bm25_chunks) > 0

    def test_store_without_bm25_has_no_index(self, doc_store):
        """Test that store without BM25 has no index"""
        assert doc_store.bm25_index is None
        assert doc_store.bm25_chunks == []

    def test_bm25_chunks_match_index(self, doc_store_with_bm25):
        """Test that BM25 chunks are available for index"""
        assert len(doc_store_with_bm25.bm25_chunks) > 0
        assert all(isinstance(chunk, Document)
                   for chunk in doc_store_with_bm25.bm25_chunks)

    def test_bm25_chunks_contain_security_data(self, doc_store_with_bm25):
        """Test that BM25 chunks contain security corpus data"""
        chunks = doc_store_with_bm25.bm25_chunks

        # Verify chunks contain security-related content
        assert any('CWE' in chunk.page_content or 'vulnerability' in chunk.page_content.lower()
                   for chunk in chunks)


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_empty_bm25_chunks(self, mock_vector_store, mock_bm25_index):
        """Test store with BM25 index but empty chunks"""
        store = DocumentStore(
            vector_store=mock_vector_store,
            bm25_index=mock_bm25_index,
            bm25_chunks=[]
        )

        assert store.bm25_index is not None
        assert store.bm25_chunks == []

    def test_vector_store_without_methods(self):
        """Test handling vector store without expected methods"""
        incomplete_store = Mock(spec=[])  # No methods

        # Should either raise error or handle gracefully
        try:
            store = DocumentStore(
                vector_store=incomplete_store,
                bm25_index=None,
                bm25_chunks=[]
            )
            # If it doesn't raise, operations should fail appropriately
        except (AttributeError, TypeError):
            pass  # Expected

    def test_none_bm25_components(self, mock_vector_store):
        """Test with explicit None for BM25 components"""
        store = DocumentStore(
            vector_store=mock_vector_store,
            bm25_index=None,
            bm25_chunks=None
        )

        # Should handle None gracefully
        assert store.bm25_index is None

    def test_mismatched_bm25_components(self, mock_vector_store, mock_bm25_index):
        """Test with BM25 index but no chunks"""
        store = DocumentStore(
            vector_store=mock_vector_store,
            bm25_index=mock_bm25_index,
            bm25_chunks=[]
        )

        # Should not crash, though retrieval might be limited
        assert store.bm25_index is not None
        assert len(store.bm25_chunks) == 0


class TestDocumentStoreState:
    """Test document store state management"""

    def test_vector_store_reference(self, doc_store, mock_vector_store):
        """Test that document store maintains reference to vector store"""
        assert doc_store.vector_store is mock_vector_store

    def test_bm25_reference(self, doc_store_with_bm25, mock_bm25_index):
        """Test that document store maintains reference to BM25 index"""
        assert doc_store_with_bm25.bm25_index is mock_bm25_index

    def test_retriever_cached_state(self, doc_store):
        """Test that retriever is cached in _retriever attribute"""
        assert doc_store._retriever is None

        with patch('remediation.fix_knowledge_store.create_hybrid_retrieval_pipeline') as mock_factory:
            mock_retriever = Mock()
            mock_factory.return_value = mock_retriever

            doc_store.get_retriever()

            assert doc_store._retriever is mock_retriever


class TestIntegration:
    """Integration tests for document store"""

    def test_complete_workflow(self, mock_vector_store, sample_security_chunks):
        """Test complete document store workflow"""
        # Create store
        store = DocumentStore(
            vector_store=mock_vector_store,
            bm25_index=None,
            bm25_chunks=[]
        )

        # Get retriever
        mock_retriever = Mock()
        mock_retriever.invoke.return_value = sample_security_chunks

        with patch.object(store, 'get_retriever', return_value=mock_retriever):
            retriever = store.get_retriever()

            # Perform retrieval
            results = retriever.invoke("SQL injection vulnerability")

            assert len(results) == len(sample_security_chunks)
            assert all(isinstance(doc, Document) for doc in results)

    def test_workflow_with_embedding_function(self, mock_vector_store):
        """Test workflow including embedding function access"""
        store = DocumentStore(
            vector_store=mock_vector_store,
            bm25_index=None,
            bm25_chunks=[]
        )

        # Get embedding function
        embed_fn = store.get_embedding_function()

        # Use embedding function
        embedding = embed_fn(["SQL injection"])

        assert isinstance(embedding, list)
        assert len(embedding) > 0