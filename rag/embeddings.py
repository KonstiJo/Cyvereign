"""
rag/embeddings.py
=================
Handles local text embeddings using HuggingFace sentence-transformers.

Embeddings convert text into dense numerical vectors so that semantically
similar passages end up close together in vector space.  ChromaDB then stores
these vectors and performs fast nearest-neighbour searches at query time.

No internet connection or API key is required – the model is downloaded once
and cached locally by the `sentence-transformers` library.
"""

import os
from langchain_community.embeddings import HuggingFaceEmbeddings
from dotenv import load_dotenv

load_dotenv()

# Default embedding model – small (80 MB), fast, and works well for English.
# You can swap this for a larger model for better accuracy, e.g.:
#   "sentence-transformers/all-mpnet-base-v2"  (~420 MB, slower)
DEFAULT_EMBEDDING_MODEL: str = os.getenv(
    "EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2"
)


def get_embedding_function(model_name: str = DEFAULT_EMBEDDING_MODEL) -> HuggingFaceEmbeddings:
    """
    Return a LangChain-compatible embedding function backed by a local
    HuggingFace sentence-transformer model.

    Parameters
    ----------
    model_name: HuggingFace model ID or local path.

    Returns
    -------
    HuggingFaceEmbeddings instance ready to be passed to a vector store.
    """
    # model_kwargs: run on CPU by default; switch to {"device": "cuda"} for GPU
    embeddings = HuggingFaceEmbeddings(
        model_name=model_name,
        model_kwargs={"device": "cpu"},
        encode_kwargs={"normalize_embeddings": True},  # cosine similarity
    )
    return embeddings
