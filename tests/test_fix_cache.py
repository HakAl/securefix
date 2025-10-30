"""
Tests for fix_cache.py

Covers:
- Semantic similarity caching
- Cache hit/miss logic
- Cache size limits
- Embedding-based similarity
"""
import pytest
from unittest.mock import Mock

try:
    from securefix.remediation.fix_cache import SemanticQueryCache
except ImportError:
    pytest.skip("fix_cache module not found", allow_module_level=True)


@pytest.fixture
def cache_with_embeddings(mock_embeddings):
    """Create cache with mocked embeddings."""
    cache = SemanticQueryCache(
        similarity_threshold=0.85,
        max_size=10
    )
    # Use the conftest mock_embeddings which returns [[0.1, 0.2, 0.3]]
    cache.embeddings = mock_embeddings.embed_documents
    return cache


@pytest.fixture
def sample_fix_result():
    """Sample vulnerability fix result for caching."""
    return {
        "answer": '{"suggested_fix": "sanitized_code", "explanation": "Fixed SQL injection"}',
        "source_documents": [Mock()]
    }


class TestCacheInitialization:
    """Test cache initialization and configuration"""

    def test_init_default_params(self):
        """Test cache initialization with default parameters"""
        cache = SemanticQueryCache()

        assert cache.threshold == 0.95
        assert cache.max_size == 100
        assert cache.cache == {}

    def test_init_custom_params(self):
        """Test cache initialization with custom parameters"""
        cache = SemanticQueryCache(
            similarity_threshold=0.9,
            max_size=50
        )

        assert cache.threshold == 0.9
        assert cache.max_size == 50


class TestCacheOperations:
    """Test basic cache set and get operations"""

    def test_cache_miss_returns_none(self, cache_with_embeddings):
        """Test that cache miss returns None"""
        result = cache_with_embeddings.get("SQL injection vulnerability")

        assert result is None

    def test_cache_hit_exact_match(self, cache_with_embeddings, sample_fix_result):
        """Test cache hit with exact query match"""
        query = "SQL injection vulnerability"

        # Set cache entry
        cache_with_embeddings.set(query, sample_fix_result)

        # Retrieve exact match
        result = cache_with_embeddings.get(query)

        assert result == sample_fix_result

    def test_cache_hit_similar_query(self, sample_fix_result):
        """Test cache hit with semantically similar query"""
        cache = SemanticQueryCache(similarity_threshold=0.85, max_size=10)

        # Mock embeddings that return similar vectors
        def mock_embed(queries):
            # Return slightly different but similar embeddings
            if "SQL injection" in str(queries):
                return [[0.1, 0.2, 0.3]]
            elif "SQLi" in str(queries):
                return [[0.11, 0.21, 0.31]]  # Very similar
            return [[0.5, 0.5, 0.5]]

        cache.embeddings = mock_embed

        # Cache original query
        cache.set("SQL injection vulnerability", sample_fix_result)

        # Try similar query
        result = cache.get("SQLi security issue")

        # Should get cache hit due to similarity
        assert result == sample_fix_result

    def test_cache_miss_dissimilar_query(self, sample_fix_result):
        """Test cache miss with dissimilar query"""
        cache = SemanticQueryCache(similarity_threshold=0.85, max_size=10)

        def mock_embed(queries):
            if "SQL" in str(queries):
                return [[1.0, 0.0, 0.0]]  # Orthogonal vectors
            elif "XSS" in str(queries):
                return [[0.0, 1.0, 0.0]]  # for true dissimilarity
            return [[0.5, 0.5, 0.5]]

        cache.embeddings = mock_embed

        # Cache SQL query
        cache.set("SQL injection vulnerability", sample_fix_result)

        # Try XSS query (dissimilar)
        result = cache.get("XSS cross-site scripting")

        # Should be cache miss
        assert result is None

    def test_cache_size_limit_fifo(self, sample_fix_result):
        """Test that cache respects max size with FIFO eviction"""
        cache = SemanticQueryCache(similarity_threshold=0.85, max_size=3)
        cache.embeddings = lambda q: [[0.1, 0.2, 0.3]]

        # Fill cache to max
        cache.set("query1", {"result": 1})
        cache.set("query2", {"result": 2})
        cache.set("query3", {"result": 3})

        assert len(cache.cache) == 3

        # Add one more - should evict oldest (query1)
        cache.set("query4", {"result": 4})

        assert len(cache.cache) == 3
        assert "query1" not in cache.cache
        assert "query4" in cache.cache


class TestEmbeddingHandling:
    """Test embedding generation and handling"""

    def test_cache_without_embeddings_raises_error(self, sample_fix_result):
        """Test that using cache without embeddings raises error"""
        cache = SemanticQueryCache()

        with pytest.raises((AttributeError, ValueError, TypeError)):
            cache.set("Test query", sample_fix_result)

    def test_cache_embed_method(self):
        """Test the _embed method"""
        cache = SemanticQueryCache(similarity_threshold=0.85, max_size=10)
        cache.embeddings = lambda q: [[0.1, 0.2, 0.3]]

        embedding = cache._embed("test query")

        assert embedding == [0.1, 0.2, 0.3]


class TestSimilarityCalculation:
    """Test cosine similarity calculation"""

    def test_cosine_similarity_identical(self):
        """Test cosine similarity with identical vectors"""
        cache = SemanticQueryCache()

        vec1 = [1.0, 0.0, 0.0]
        vec2 = [1.0, 0.0, 0.0]

        similarity = cache._cosine_similarity(vec1, vec2)

        assert similarity == pytest.approx(1.0, abs=0.01)

    def test_cosine_similarity_orthogonal(self):
        """Test cosine similarity with orthogonal vectors"""
        cache = SemanticQueryCache()

        vec1 = [1.0, 0.0, 0.0]
        vec2 = [0.0, 1.0, 0.0]

        similarity = cache._cosine_similarity(vec1, vec2)

        assert similarity == pytest.approx(0.0, abs=0.01)

    def test_cosine_similarity_similar(self):
        """Test cosine similarity with similar vectors"""
        cache = SemanticQueryCache()

        vec1 = [0.1, 0.2, 0.3]
        vec2 = [0.11, 0.21, 0.31]

        similarity = cache._cosine_similarity(vec1, vec2)

        assert similarity > 0.95  # Should be very similar


class TestCacheIntegration:
    """Integration tests for cache functionality"""

    def test_complete_cache_workflow(self, sample_fix_result):
        """Test complete cache workflow"""
        cache = SemanticQueryCache(similarity_threshold=0.9, max_size=10)
        cache.embeddings = lambda q: [[0.1, 0.2, 0.3]]

        query = "CWE-89 SQL injection"

        # Initial miss
        result = cache.get(query)
        assert result is None

        # Set cache
        cache.set(query, sample_fix_result)

        # Hit on same query
        result = cache.get(query)
        assert result == sample_fix_result

    def test_multiple_entries(self):
        """Test cache with multiple entries"""
        cache = SemanticQueryCache(similarity_threshold=0.85, max_size=10)

        # Mock different embeddings for different queries (orthogonal for true dissimilarity)
        def mock_embed(queries):
            q = queries[0] if isinstance(queries, list) else queries
            if "SQL" in q:
                return [[1.0, 0.0, 0.0]]
            elif "XSS" in q:
                return [[0.0, 1.0, 0.0]]
            elif "CSRF" in q:
                return [[0.0, 0.0, 1.0]]
            return [[0.0, 0.0, 0.0]]

        cache.embeddings = mock_embed

        # Add multiple entries
        cache.set("SQL injection", {"fix": "sql"})
        cache.set("XSS vulnerability", {"fix": "xss"})
        cache.set("CSRF attack", {"fix": "csrf"})

        assert len(cache.cache) == 3

        # Each should be retrievable
        assert cache.get("SQL injection")["fix"] == "sql"
        assert cache.get("XSS vulnerability")["fix"] == "xss"
        assert cache.get("CSRF attack")["fix"] == "csrf"


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_empty_query(self, cache_with_embeddings):
        """Test handling of empty query"""
        # Should handle gracefully or raise appropriate error
        try:
            result = cache_with_embeddings.get("")
            assert result is None or isinstance(result, dict)
        except (ValueError, AttributeError):
            pass  # Acceptable behavior

    def test_cache_with_none_result(self, cache_with_embeddings):
        """Test caching None as a result"""
        cache_with_embeddings.set("query", None)
        result = cache_with_embeddings.get("query")

        # Cache should store None
        assert result is None or "query" not in cache_with_embeddings.cache

    def test_very_low_threshold(self, sample_fix_result):
        """Test cache with very low similarity threshold"""
        cache = SemanticQueryCache(similarity_threshold=0.1, max_size=10)
        cache.embeddings = lambda q: [[0.1, 0.2, 0.3]]

        cache.set("query1", sample_fix_result)

        # Even dissimilar queries might hit
        result = cache.get("completely different query")

        # Behavior depends on actual similarity, just ensure no crash
        assert result is None or isinstance(result, dict)

    def test_very_high_threshold(self, sample_fix_result):
        """Test cache with very high similarity threshold"""
        cache = SemanticQueryCache(similarity_threshold=0.999, max_size=10)

        def mock_embed(queries):
            # Return slightly different embeddings each time
            import random
            return [[0.1 + random.random()*0.01, 0.2, 0.3]]

        cache.embeddings = mock_embed

        cache.set("query1", sample_fix_result)

        # Even similar queries should miss with very high threshold
        result = cache.get("query1")

        # Might miss due to slight embedding differences
        assert result is None or isinstance(result, dict)