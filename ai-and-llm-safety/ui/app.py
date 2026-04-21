import streamlit as st
import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ['OPENAI_API_KEY'] = ''

from src.chat import ChatSession
from src.ingest import ingest_documents, get_collection_info
from src.config import DOCS_DIR


st.set_page_config(page_title="RAG Chatbot", page_icon="🤖", layout="wide")

st.title("🤖 RAG Chatbot")
st.markdown("*Ask questions about your documents*")

if "session" not in st.session_state:
    st.session_state.session = ChatSession()
    st.session_state.messages = []

info = st.session_state.session.get_info()
st.sidebar.markdown(f"**Collection:** {info.get('name', 'N/A')}")
st.sidebar.markdown(f"**Documents:** {info.get('count', 0)}")

with st.sidebar.expander("📁 Document Management"):
    if st.button("🔄 Re-ingest docs"):
        with st.spinner("Ingesting..."):
            result = ingest_documents(str(DOCS_DIR), clear_existing=True)
            st.success(f"Ingested {result.get('chunks', 0)} chunks from {result.get('documents', 0)} docs")
            st.rerun()

    if st.button("📊 Collection Info"):
        info = get_collection_info("documents")
        st.json(info)

with st.sidebar.expander("🧹 Controls"):
    if st.button("Clear Chat History"):
        st.session_state.session.clear_history()
        st.session_state.messages = []
        st.rerun()

    use_rag = st.checkbox("Use RAG (document context)", value=True)
    st.session_state.use_rag = use_rag

st.markdown("---")

for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

query = st.chat_input("Ask a question about your documents...")

if query:
    with st.chat_message("user"):
        st.markdown(query)

    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            if st.session_state.use_rag:
                result = st.session_state.session.chat(query)
                response = result["response"]
                if result.get("sources"):
                    with st.expander("📄 Sources"):
                        for s in result["sources"][:2]:
                            st.markdown(f"- {s['content'][:200]}...")
            else:
                response = st.session_state.session.chat_no_rag(query)
        st.markdown(response)

    st.session_state.messages.append({"role": "user", "content": query})
    st.session_state.messages.append({"role": "assistant", "content": response})