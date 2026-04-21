from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

os.environ['OPENAI_API_KEY'] = ''

from src.chat import ChatSession
from src.ingest import ingest_documents, get_collection_info, ingest_file
from src.config import DOCS_DIR

app = FastAPI(
    title="RAG Chatbot API",
    description="Secure RAG chatbot with prompt injection testing endpoints",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000)
    use_rag: bool = Field(default=True)
    session_id: Optional[str] = None


class ChatResponse(BaseModel):
    response: str
    sources: List[dict] = []
    session_id: str
    context_used: bool = False


class IngestRequest(BaseModel):
    directory: Optional[str] = None
    clear_existing: bool = False


class IngestFileRequest(BaseModel):
    file_path: str


class HealthResponse(BaseModel):
    status: str
    collection_count: int
    model: str


sessions = {}


@app.get("/", response_model=dict)
async def root():
    return {"message": "RAG Chatbot API", "version": "1.0.0", "docs": "/docs"}


@app.get("/health", response_model=HealthResponse)
async def health():
    info = get_collection_info("documents")
    return HealthResponse(
        status="healthy",
        collection_count=info.get("count", 0),
        model="gemma4:e4b"
    )


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    try:
        session_key = request.session_id or "default"
        
        if session_key not in sessions:
            sessions[session_key] = ChatSession()
        
        session = sessions[session_key]
        
        if request.use_rag:
            result = session.chat(request.message)
        else:
            response = session.chat_no_rag(request.message)
            result = {
                "response": response,
                "sources": [],
                "context_used": False
            }
        
        return ChatResponse(
            response=result.get("response", ""),
            sources=result.get("sources", []),
            session_id=session_key,
            context_used=result.get("context_used", False)
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ingest", response_model=dict)
async def ingest(request: IngestRequest):
    try:
        directory = request.directory or str(DOCS_DIR)
        result = ingest_documents(directory, clear_existing=request.clear_existing)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ingest/file", response_model=dict)
async def ingest_file_endpoint(request: IngestFileRequest):
    try:
        result = ingest_file(request.file_path)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/info", response_model=dict)
async def info():
    try:
        return get_collection_info("documents")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
    if session_id in sessions:
        sessions[session_id].clear_history()
        del sessions[session_id]
        return {"status": "deleted", "session_id": session_id}
    raise HTTPException(status_code=404, detail="Session not found")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)