from typing import List, Optional
from .embed import VectorStore
from .config import TOP_K, RETRIEVE_SYSTEM_PROMPT


class Retriever:
    def __init__(self, collection_name: str = "documents"):
        self.vector_store = VectorStore(collection_name)

    def retrieve(self, query: str, top_k: int = TOP_K) -> List[dict]:
        return self.vector_store.similarity_search(query, top_k)

    def build_context(self, query: str, top_k: Optional[int] = None) -> str:
        docs = self.retrieve(query, top_k or TOP_K)
        if not docs:
            return "No relevant documents found."

        context_parts = []
        for i, doc in enumerate(docs, 1):
            context_parts.append(f"[Document {i}]\n{doc['content']}")

        return "\n\n".join(context_parts)

    def get_relevant_docs(self, query: str, top_k: int = TOP_K) -> List[dict]:
        return self.retrieve(query, top_k)