from typing import List, Optional
import chromadb
from .config import CHROMA_DIR
from .models import llm_manager


_client = None


def get_client():
    global _client
    if _client is None:
        _client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    return _client


class VectorStore:
    def __init__(self, collection_name: str = "documents"):
        self.collection_name = collection_name
        self.client = get_client()
        try:
            self.collection = self.client.get_collection(name=collection_name)
        except Exception:
            self.collection = self.client.create_collection(
                name=collection_name,
                metadata={"hnsw:space": "cosine"}
            )
        self.embed_model = "nomic-embed-text"

    def add_texts(self, texts: List[str], ids: List[str], metadata: Optional[List[dict]] = None):
        embeddings = []
        for text in texts:
            emb = llm_manager.embed(text)
            embeddings.append(emb)

        self.collection.add(
            embeddings=embeddings,
            documents=texts,
            ids=ids,
            metadatas=metadata or [{}] * len(texts)
        )

    def similarity_search(self, query: str, top_k: int = 5) -> List[dict]:
        try:
            count = self.collection.count()
        except Exception:
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"}
            )
            count = self.collection.count()
        
        if count == 0:
            return []
        
        query_emb = llm_manager.embed(query)
        n_results = min(top_k, count)
        results = self.collection.query(
            query_embeddings=[query_emb],
            n_results=n_results
        )

        if not results["documents"] or not results["documents"][0]:
            return []
            
        docs = []
        for i, doc in enumerate(results["documents"][0]):
            docs.append({
                "content": doc,
                "id": results["ids"][0][i],
                "distance": results["distances"][0][i],
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {}
            })
        return docs

    def delete_collection(self):
        self.client.delete_collection(name=self.collection.name)

    def count(self) -> int:
        return self.collection.count()