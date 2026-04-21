import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ['OPENAI_API_KEY'] = ''

from src.chat import ChatSession
from src.ingest import ingest_documents, get_collection_info
from src.config import DOCS_DIR


def print_help():
    print("""
Commands:
  ask <question>    - Ask a question (with RAG context)
  ask-no-rag <q>    - Ask without document context
  ingest            - Re-ingest documents from docs/
  info              - Show collection info
  clear             - Clear chat history
  history           - Show conversation history
  help              - Show this help
  exit/quit         - Exit the chat
""")


def main():
    session = ChatSession()
    print("RAG Chatbot CLI")
    print("Type 'help' for commands\n")

    while True:
        try:
            user_input = input("You: ").strip()

            if not user_input:
                continue

            if user_input.lower() in ["exit", "quit"]:
                print("Goodbye!")
                break

            parts = user_input.split(" ", 1)
            cmd = parts[0].lower()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd == "help":
                print_help()

            elif cmd == "ask":
                if not arg:
                    print("Usage: ask <question>")
                    continue
                result = session.chat(arg)
                print(f"\nBot: {result['response']}\n")
                if result.get("sources"):
                    print(f"[Using {len(result['sources'])} document chunks]\n")

            elif cmd == "ask-no-rag":
                if not arg:
                    print("Usage: ask-no-rag <question>")
                    continue
                response = session.chat_no_rag(arg)
                print(f"\nBot: {response}\n")

            elif cmd == "ingest":
                print("Ingesting documents...")
                result = ingest_documents(str(DOCS_DIR), clear_existing=True)
                print(f"Done: {result.get('chunks', 0)} chunks from {result.get('documents', 0)} docs\n")

            elif cmd == "info":
                info = get_collection_info("documents")
                print(f"\nCollection: {info.get('name', 'N/A')}")
                print(f"Documents: {info.get('count', 0)}\n")

            elif cmd == "clear":
                session.clear_history()
                print("Chat history cleared\n")

            elif cmd == "history":
                hist = session.get_history()
                print("\nConversation History:")
                for i, msg in enumerate(hist, 1):
                    print(f"  {i}. [{msg['role']}]: {msg['content'][:80]}...")
                print()

            else:
                print(f"Unknown command: {cmd}. Type 'help' for available commands.\n")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            import traceback
            print(f"Error: {e}\n")
            traceback.print_exc()


if __name__ == "__main__":
    main()