import os
import json
import logging
import time
import yaml
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from typing import List, Dict, NamedTuple, Optional, Tuple

from remediation.config import app_config
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_huggingface import HuggingFaceEmbeddings
from rank_bm25 import BM25Okapi
from tqdm import tqdm

import csv
import markdown

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class LoadResult(NamedTuple):
    """Data structure for returning loader results."""
    loaded_documents: List[Document]
    failed_files: List[Dict[str, str]]


class ProgressEmbeddings(Embeddings):
    """Wrapper class that tracks embedding progress with tqdm."""

    def __init__(self, base_embeddings, total_chunks):
        self.base = base_embeddings
        self.pbar = tqdm(total=total_chunks, desc="Embedding chunks")
        self.embedded_count = 0

    def embed_documents(self, texts):
        result = self.base.embed_documents(texts)
        self.pbar.update(len(texts))
        self.embedded_count += len(texts)
        return result

    def embed_query(self, text):
        return self.base.embed_query(text)

    def close(self):
        self.pbar.close()


@contextmanager
def create_progress_embeddings(base_embeddings, total_chunks):
    """Context manager for progress-tracked embeddings."""
    wrapper = ProgressEmbeddings(base_embeddings, total_chunks)
    try:
        yield wrapper
    finally:
        wrapper.close()


class DocumentProcessor:
    def __init__(self, persist_directory="./chroma_db", api_key=None):
        self.persist_directory = persist_directory
        self.api_key = api_key
        self.embeddings = self._setup_embeddings()
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=app_config.chunking.chunk_size,
            chunk_overlap=app_config.chunking.chunk_overlap,
            length_function=len,
        )
        self.bm25_index = None
        self.bm25_chunks = None
        self.supported_extensions = {'.csv', '.md', '.yaml', '.yml'}

    def _setup_embeddings(self):
        """Setup embeddings with caching enabled"""
        try:
            return HuggingFaceEmbeddings(
                model_name="sentence-transformers/all-MiniLM-L6-v2",
                model_kwargs={'device': 'cpu'},
                encode_kwargs={'normalize_embeddings': False},
                cache_folder="./model_cache"
            )
        except ImportError:
            from langchain.embeddings import FakeEmbeddings
            return FakeEmbeddings(size=384)

    def load_security_corpus(self, file_path: str, retries: int = 2, delay: int = 1) -> List[Document]:
        """
        Load security fix patterns from various file formats.

        Supports:
        - CSV files (CWE data)
        - Markdown files (OWASP cheat sheets)
        - YAML files (PyPA advisory database)
        """
        file_ext = Path(file_path).suffix.lower()

        for attempt in range(retries + 1):
            try:
                if file_ext == '.csv':
                    return self._load_cwe_csv(file_path)
                elif file_ext == '.md':
                    return self._load_owasp_markdown(file_path)
                elif file_ext in ['.yaml', '.yml']:
                    return self._load_pypa_yaml(file_path)
                else:
                    logging.warning(f"Unsupported file type: {file_ext} for {file_path}")
                    return []

            except Exception as e:
                if attempt < retries:
                    wait_time = delay * (2 ** attempt)
                    logging.warning(f"Attempt {attempt + 1} failed for {file_path}: {e}. Retrying in {wait_time}s...")
                    time.sleep(wait_time)
                else:
                    raise

    def _load_cwe_csv(self, file_path: str) -> List[Document]:
        """Load CWE data from CSV format."""
        documents = []

        with open(file_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Extract key fields from CWE CSV
                cwe_id = row.get('CWE-ID', 'Unknown')
                name = row.get('Name', '')
                description = row.get('Description', '')
                extended_desc = row.get('Extended Description', '')
                mitigations = row.get('Potential Mitigations', '')

                # Construct page content
                content = f"CWE-{cwe_id}: {name}\n\n"
                content += f"Description: {description}\n\n"

                if extended_desc:
                    content += f"Extended Description: {extended_desc}\n\n"

                if mitigations:
                    content += f"Mitigations:\n{mitigations}"

                doc = Document(
                    page_content=content,
                    metadata={
                        "source": file_path,
                        "cwe_id": f"CWE-{cwe_id}",
                        "vulnerability_type": name,
                        "doc_type": "cwe",
                        "weakness_abstraction": row.get('Weakness Abstraction', ''),
                    }
                )
                documents.append(doc)

        logging.info(f"Loaded {len(documents)} CWE entries from {Path(file_path).name}")
        return documents

    def _load_owasp_markdown(self, file_path: str) -> List[Document]:
        """Load OWASP cheat sheet from Markdown format."""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Convert markdown to plain text for better processing
        # Keep the markdown structure for context

        # Extract title from filename or first heading
        filename = Path(file_path).stem
        title = filename.replace('_', ' ').title()

        doc = Document(
            page_content=content,
            metadata={
                "source": file_path,
                "title": title,
                "doc_type": "owasp_cheatsheet",
                "format": "markdown"
            }
        )

        logging.info(f"Loaded OWASP cheat sheet from {Path(file_path).name}")
        return [doc]

    def _load_pypa_yaml(self, file_path: str) -> List[Document]:
        """Load PyPA advisory data from YAML format."""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        # Extract key fields from PyPA advisory
        vuln_id = data.get('id', 'Unknown')
        details = data.get('details', '')
        affected = data.get('affected', [])
        references = data.get('references', [])
        aliases = data.get('aliases', [])

        # Construct page content
        content = f"Vulnerability ID: {vuln_id}\n\n"
        content += f"Details: {details}\n\n"

        if affected:
            content += "Affected Packages:\n"
            for pkg in affected:
                pkg_info = pkg.get('package', {})
                content += f"  - {pkg_info.get('name', 'Unknown')} ({pkg_info.get('ecosystem', 'Unknown')})\n"

                ranges = pkg.get('ranges', [])
                if ranges:
                    for range_info in ranges:
                        events = range_info.get('events', [])
                        for event in events:
                            content += f"    - {list(event.keys())[0]}: {list(event.values())[0]}\n"

        if references:
            content += "\nReferences:\n"
            for ref in references:
                content += f"  - [{ref.get('type', 'LINK')}] {ref.get('url', '')}\n"

        doc = Document(
            page_content=content,
            metadata={
                "source": file_path,
                "vulnerability_id": vuln_id,
                "doc_type": "pypa_advisory",
                "aliases": aliases,
                "cve_ids": [alias for alias in aliases if alias.startswith('CVE-')]
            }
        )

        logging.info(f"Loaded PyPA advisory from {Path(file_path).name}")
        return [doc]

    def load_documents(self, documents_folder: str = "remediation/corpus", retries: int = 2,
                       delay: int = 1) -> LoadResult:
        """
        Load security corpus documents with robust parallel processing.

        Args:
            documents_folder: The folder to load files from (default: remediation/corpus)
            retries: The number of times to retry loading a failed document.
            delay: The initial delay in seconds between retries.

        Returns:
            A LoadResult object containing lists of loaded documents and failed files.
        """
        if not os.path.exists(documents_folder):
            logging.warning(f"Folder '{documents_folder}' not found.")
            return LoadResult([], [])

        file_paths = [
            os.path.join(documents_folder, f)
            for f in os.listdir(documents_folder)
            if any(f.lower().endswith(ext) for ext in self.supported_extensions)
        ]

        if not file_paths:
            logging.info(f"No supported files found in '{documents_folder}'.")
            logging.info(f"Supported formats: {', '.join(sorted(self.supported_extensions))}")
            return LoadResult([], [])

        loaded_docs: List[Document] = []
        failed_files: List[Dict[str, str]] = []
        max_workers = min(len(file_paths), os.cpu_count() or 4, 8)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_path = {
                executor.submit(self.load_security_corpus, fp, retries, delay): fp
                for fp in file_paths
            }

            with tqdm(total=len(file_paths), desc="📄 Loading security corpus") as pbar:
                for future in as_completed(future_to_path):
                    file_path = future_to_path[future]
                    try:
                        docs = future.result()
                        if docs:
                            loaded_docs.extend(docs)
                    except Exception as e:
                        failed_files.append({"path": file_path, "error": str(e)})
                        logging.error(f"Failed to process {os.path.basename(file_path)} after all retries: {e}")
                    finally:
                        pbar.update(1)

        return LoadResult(loaded_documents=loaded_docs, failed_files=failed_files)

    def _build_bm25_index(self, chunks: List[Document]) -> Tuple[BM25Okapi, List[Document]]:
        """Build BM25 index with pre-tokenized corpus"""
        print("Building BM25 index...")
        tokenized = [doc.page_content.lower().split() for doc in chunks]
        return BM25Okapi(tokenized), chunks

    def _split_documents_batch(self, documents: List[Document]) -> List[Document]:
        return self.text_splitter.split_documents(documents)

    def process_documents(self, documents_folder: str = "remediation/corpus") -> Optional[Tuple]:
        """
        Loads, splits, and indexes security corpus documents.
        """
        logging.info("Loading security corpus...")
        load_result = self.load_documents(documents_folder)

        if load_result.failed_files:
            logging.warning(f"Encountered {len(load_result.failed_files)} loading errors:")
            for failed in load_result.failed_files:
                logging.warning(f"  - File: {os.path.basename(failed['path'])}, Error: {failed['error']}")

        if not load_result.loaded_documents:
            logging.error("No documents were successfully loaded!")
            logging.info(f"   Please check the files in '{documents_folder}' and review any errors above.")
            return None

        documents = load_result.loaded_documents
        logging.info(f"Successfully loaded {len(documents)} security corpus documents.")

        logging.info("Splitting into chunks...")
        split_chunks = self._split_documents_batch(documents)
        logging.info(f"Created {len(split_chunks)} chunks.")

        # Build BM25 index
        self.bm25_index, self.bm25_chunks = self._build_bm25_index(split_chunks)

        # Create vector store
        logging.info("🗄️ Creating vector database...")
        vector_store = self._create_vectorstore_batched(split_chunks)

        logging.info("Vector database created successfully!")
        return vector_store, self.bm25_index, self.bm25_chunks

    def _create_vectorstore_batched(self, chunks: List[Document]) -> Chroma:
        """Create vector store with progress tracking via context manager."""
        with create_progress_embeddings(self.embeddings, len(chunks)) as prog_emb:
            vector_store = Chroma.from_documents(
                documents=chunks,
                embedding=prog_emb,
                persist_directory=self.persist_directory,
                collection_metadata={"hnsw:space": "cosine"}
            )
        return vector_store

    def load_existing_vectorstore(self) -> Tuple[Optional[Chroma], Optional[BM25Okapi], Optional[List[Document]]]:
        """Load existing vector store and rebuild BM25 index"""
        if not os.path.exists(self.persist_directory):
            print(f"No existing vector store found at '{self.persist_directory}'")
            return None, None, None

        try:
            print("Loading existing vector store...")
            vs = Chroma(
                persist_directory=self.persist_directory,
                embedding_function=self.embeddings
            )

            # Rebuild BM25 from stored chunks
            print("Rebuilding BM25 index...")
            raw = vs.get()

            if not raw["documents"]:
                print("Vector store is empty")
                return vs, None, None

            chunks = [
                Document(page_content=doc, metadata=meta)
                for doc, meta in zip(raw["documents"], raw["metadatas"])
            ]

            self.bm25_index, self.bm25_chunks = self._build_bm25_index(chunks)
            print(f"Loaded {len(chunks)} chunks from existing store")

            return vs, self.bm25_index, self.bm25_chunks

        except Exception as e:
            print(f"Error loading vector store: {e}")
            return None, None, None