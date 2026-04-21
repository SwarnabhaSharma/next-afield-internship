from typing import Optional, List
from openai import OpenAI
from .config import (
    OLLAMA_BASE_URL,
    OLLAMA_MODEL,
    OLLAMA_EMBED_MODEL,
    OLLAMA_API_KEY,
    OLLAMA_USE_CLOUD,
    OPENAI_API_KEY,
    OPENAI_MODEL,
    OPENAI_BASE_URL,
)


class OllamaClient:
    def __init__(self, base_url: str = OLLAMA_BASE_URL, api_key: str = OLLAMA_API_KEY, use_cloud: bool = False):
        self.use_cloud = use_cloud
        if use_cloud:
            self.client = OpenAI(
                api_key=api_key or "ollama",
                base_url=f"{base_url}/v1" if not base_url.endswith("/v1") else base_url
            )
        else:
            self.client = None
            self.base_url = base_url
        self.model = OLLAMA_MODEL
        self.embed_model = OLLAMA_EMBED_MODEL

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        if self.use_cloud:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages
            )
            return response.choices[0].message.content
        else:
            import ollama
            response = ollama.chat(model=self.model, messages=messages)
            return response["message"]["content"]

    def embed(self, text: str) -> List[float]:
        if self.use_cloud:
            response = self.client.embeddings.create(
                model=self.embed_model,
                input=text
            )
            return response.data[0].embedding
        else:
            import ollama
            response = ollama.embeddings(
                model=self.embed_model,
                prompt=text
            )
            return response["embedding"]


class OpenAIClient:
    def __init__(self, api_key: str = OPENAI_API_KEY, base_url: str = OPENAI_BASE_URL):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = OPENAI_MODEL

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages
        )
        return response.choices[0].message.content

    def embed(self, text: str) -> List[float]:
        response = self.client.embeddings.create(
            model="text-embedding-3-small",
            input=text
        )
        return response.data[0].embedding


class LLMManager:
    def __init__(self):
        self.use_cloud = OLLAMA_USE_CLOUD and OLLAMA_API_KEY
        self.use_openai = bool(OPENAI_API_KEY) and OPENAI_API_KEY != ""

        if self.use_cloud:
            self.ollama = OllamaClient(use_cloud=True)
            self.openai = None
        elif self.use_openai:
            self.ollama = None
            self.openai = OpenAIClient()
        else:
            self.ollama = OllamaClient(use_cloud=False)
            self.openai = None

    def generate(self, prompt: str, system: Optional[str] = None) -> str:
        if self.use_cloud and self.ollama:
            return self.ollama.generate(prompt, system)
        elif self.use_openai and self.openai:
            return self.openai.generate(prompt, system)
        elif self.ollama:
            return self.ollama.generate(prompt, system)
        raise RuntimeError("No LLM backend available")

    def embed(self, text: str) -> List[float]:
        if self.use_cloud and self.ollama:
            return self.ollama.embed(text)
        elif self.ollama:
            return self.ollama.embed(text)
        elif self.openai:
            return self.openai.embed(text)
        raise RuntimeError("No embedding backend available")


llm_manager = LLMManager()