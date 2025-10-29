from langchain.text_splitter import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter
from langchain_core.documents import Document
from typing import List

def process_markdown_file(file_path: str, chunk_size: int = 1000, chunk_overlap: int = 200) -> List[Document]:
    """
    Process markdown files with header-aware splitting.
    Preserves document structure and adds header hierarchy to metadata.
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        markdown = f.read()

    markdown_splitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=[
            ("#", "Header 1"),
            ("##", "Header 2"),
            ("###", "Header 3"),
        ],
        strip_headers=False
    )

    header_splits = markdown_splitter.split_text(markdown)

    # Then do recursive splitting if chunks are still too large
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", " ", ""]
    )

    final_chunks = []
    for doc in header_splits:
        # If chunk is small enough, keep it
        if len(doc.page_content) <= chunk_size:
            doc.metadata['source'] = file_path
            doc.metadata['doc_type'] = 'markdown'
            doc.metadata['pre_chunked'] = True
            final_chunks.append(doc)
        else:
            # Split further if needed
            sub_chunks = text_splitter.split_documents([doc])
            for chunk in sub_chunks:
                chunk.metadata['source'] = file_path
                chunk.metadata['doc_type'] = 'markdown'
                doc.metadata['pre_chunked'] = True
                # Preserve header metadata from parent
                if 'Header1' in doc.metadata:
                    chunk.metadata['Header1'] = doc.metadata['Header1']
                if 'Header2' in doc.metadata:
                    chunk.metadata['Header2'] = doc.metadata['Header2']
                if 'Header3' in doc.metadata:
                    chunk.metadata['Header3'] = doc.metadata['Header3']
                final_chunks.append(chunk)

    return final_chunks