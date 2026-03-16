"""
rag/vector_store.py
===================
Manages the ChromaDB vector store used for Retrieval-Augmented Generation (RAG).

Workflow:
  1. Load text documents from the /datasets/* folders.
  2. Split them into overlapping chunks (better recall for long documents).
  3. Embed each chunk with the HuggingFace embedding model.
  4. Persist the vectors in ChromaDB on disk (so we only do this once).
  5. At query time, retrieve the top-k most relevant chunks and pass them
     to the LLM as context.
"""

import os
from pathlib import Path
from typing import List

from langchain_community.document_loaders import (
    DirectoryLoader,
    TextLoader,
)
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from langchain.schema import Document

from rag.embeddings import get_embedding_function
from dotenv import load_dotenv

load_dotenv()

# Where ChromaDB persists its data between runs
CHROMA_PERSIST_DIR: str = os.getenv("CHROMA_PERSIST_DIR", "./chroma_db")

# Dataset folders that will be indexed into the vector store
DATASET_DIRS: List[str] = [
    "datasets/cve",
    "datasets/owasp",
    "datasets/pentest",
    "datasets/security_research",
]


class VectorStore:
    """
    Wrapper around ChromaDB that handles ingestion and retrieval.

    Usage:
        store = VectorStore()
        store.build_index()                         # ingest all datasets (once)
        docs = store.search("buffer overflow C")    # semantic search
    """

    def __init__(
        self,
        persist_dir: str = CHROMA_PERSIST_DIR,
        collection_name: str = "cybersec_knowledge",
    ):
        self.persist_dir = persist_dir
        self.collection_name = collection_name
        self.embeddings = get_embedding_function()

        # Initialise (or load existing) ChromaDB collection
        self.db = Chroma(
            collection_name=self.collection_name,
            embedding_function=self.embeddings,
            persist_directory=self.persist_dir,
        )

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def build_index(self, dataset_dirs: List[str] | None = None) -> int:
        """
        Load documents from all dataset directories, chunk them, embed them,
        and store them in ChromaDB.

        Parameters
        ----------
        dataset_dirs: Override the default list of directories to index.

        Returns
        -------
        Total number of chunks added to the vector store.
        """
        dirs = dataset_dirs or DATASET_DIRS
        all_docs: List[Document] = []

        for directory in dirs:
            path = Path(directory)
            if not path.exists():
                print(f"[VectorStore] Directory not found, skipping: {directory}")
                continue

        # Load .txt and .md files separately (DirectoryLoader glob does not
        # support brace expansion like *.{txt,md})
        loaded_docs: list[Document] = []
        for pattern in ["**/*.txt", "**/*.md"]:
            loader = DirectoryLoader(
                str(path),
                glob=pattern,
                loader_cls=TextLoader,
                loader_kwargs={"encoding": "utf-8"},
                silent_errors=True,
            )
            loaded_docs.extend(loader.load())
        docs = loaded_docs
            print(f"[VectorStore] Loaded {len(docs)} documents from {directory}")
            all_docs.extend(docs)

        if not all_docs:
            print("[VectorStore] No documents found. Add .txt or .md files to datasets/")
            return 0

        # Split documents into smaller overlapping chunks for better retrieval
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,     # characters per chunk
            chunk_overlap=200,   # overlap keeps context across chunk boundaries
        )
        chunks = splitter.split_documents(all_docs)
        print(f"[VectorStore] Indexing {len(chunks)} chunks …")

        # Add chunks to ChromaDB (embeddings are computed here)
        self.db.add_documents(chunks)
        print(f"[VectorStore] Done. Index persisted to: {self.persist_dir}")
        return len(chunks)

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def search(self, query: str, k: int = 4) -> List[Document]:
        """
        Semantic similarity search.

        Parameters
        ----------
        query: Natural-language query string.
        k:     Number of most-relevant chunks to return.

        Returns
        -------
        List of LangChain Document objects with `.page_content` and `.metadata`.
        """
        return self.db.similarity_search(query, k=k)

    def get_context_string(self, query: str, k: int = 4) -> str:
        """
        Convenience method: return the top-k chunks as a single context string
        ready to be injected into an LLM prompt.
        """
        docs = self.search(query, k=k)
        if not docs:
            return ""
        parts = []
        for i, doc in enumerate(docs, start=1):
            source = doc.metadata.get("source", "unknown")
            parts.append(f"[Context {i} – {source}]\n{doc.page_content}")
        return "\n\n".join(parts)
