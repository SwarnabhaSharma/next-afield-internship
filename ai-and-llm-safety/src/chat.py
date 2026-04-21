from typing import List, Optional
from .generate import Generator, create_rag_response
from .ingest import ingest_documents, get_collection_info


class ChatSession:
    def __init__(self, collection_name: str = "documents"):
        self.generator = Generator(collection_name)
        self.collection_name = collection_name
        self.history: List[dict] = []

    def chat(self, query: str, include_context: bool = True) -> dict:
        result = self.generator.generate(query, include_context=include_context)
        result["timestamp"] = "now"
        self.history.append({"role": "user", "content": query})
        self.history.append({"role": "assistant", "content": result["response"]})
        return result

    def chat_no_rag(self, query: str) -> str:
        response = self.generator.generate_without_rag(query)
        self.history.append({"role": "user", "content": query})
        self.history.append({"role": "assistant", "content": response})
        return response

    def get_history(self) -> List[dict]:
        return self.history

    def clear_history(self):
        self.history = []

    def ingest_docs(self, directory: str = None, clear_existing: bool = False) -> dict:
        return ingest_documents(directory, self.collection_name, clear_existing)

    def get_info(self) -> dict:
        return get_collection_info(self.collection_name)


def start_chat(collection_name: str = "documents") -> ChatSession:
    return ChatSession(collection_name)


def rag_chat(query: str, collection_name: str = "documents") -> dict:
    return create_rag_response(query, collection_name)