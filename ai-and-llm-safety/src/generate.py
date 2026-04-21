from typing import Optional, List
from .models import llm_manager
from .retrieve import Retriever
from .config import GENERATE_SYSTEM_PROMPT, TOP_K
from .guardrails import GuardrailManager, GuardrailDecision
from .pii_detection import PIIFilter


class Generator:
    def __init__(self, collection_name: str = "documents", enable_guardrails: bool = True):
        self.retriever = Retriever(collection_name)
        self.system_prompt = GENERATE_SYSTEM_PROMPT
        self.enable_guardrails = enable_guardrails
        
        # Initialize guardrails
        if enable_guardrails:
            self.guardrails = GuardrailManager({
                "max_input_length": 2000,
                "escape_html": True,
                "enable_pii_detection": True,
            })
            self.pii_filter = PIIFilter(sensitivity="high")
        else:
            self.guardrails = None
            self.pii_filter = None

    def _apply_input_guardrails(self, query: str) -> tuple:
        """Apply input guardrails to query
        
        Returns:
            (sanitized_query, is_allowed, block_reason, warnings)
        """
        if not self.guardrails:
            return query, True, None, []
        
        result = self.guardrails.check_input(query)
        
        if result.decision == GuardrailDecision.BLOCK:
            return "", False, result.reason, []
        
        if result.decision == GuardrailDecision.WARN:
            return result.sanitized_input, True, None, [result.reason]
        
        return result.sanitized_input, True, None, []

    def _apply_output_guardrails(self, response: str) -> tuple:
        """Apply output guardrails to response
        
        Returns:
            (filtered_response, filter_actions, pii_detected)
        """
        if not self.guardrails:
            return response, [], []
        
        # Filter output
        filtered, actions = self.guardrails.filter_output(response)
        
        # PII detection
        pii_list = []
        if self.pii_filter:
            filtered, pii_list = self.pii_filter.filter(filtered)
            if pii_list:
                actions.append("pii_redacted")
        
        return filtered, actions, pii_list

    def generate(self, query: str, top_k: Optional[int] = None, include_context: bool = True) -> dict:
        # Apply input guardrails
        sanitized_query, is_allowed, block_reason, warnings = self._apply_input_guardrails(query)
        
        if not is_allowed:
            return {
                "query": query,
                "response": f"I'm sorry, but I can't process that request. Reason: {block_reason}",
                "context_used": False,
                "sources": [],
                "blocked": True,
                "block_reason": block_reason,
                "warnings": warnings
            }
        
        # Use sanitized query for processing
        query = sanitized_query
        
        effective_top_k = top_k if top_k is not None else TOP_K
        context = ""
        if include_context:
            context = self.retriever.build_context(query, effective_top_k)

        if context == "No relevant documents found.":
            filtered_response, actions, pii = self._apply_output_guardrails(
                "I don't have relevant information in my knowledge base to answer this question."
            )
            return {
                "query": query,
                "response": filtered_response,
                "context_used": False,
                "sources": [],
                "filter_actions": actions,
                "pii_detected": pii,
                "warnings": warnings
            }

        # Get hardened system prompt
        if self.guardrails:
            system_prompt = self.guardrails.get_system_prompt("rag")
        else:
            system_prompt = self.system_prompt

        rag_prompt = f"""Based on the following context, answer the user's question.

Context:
{context}

User Question: {query}

Answer:"""

        response = llm_manager.generate(rag_prompt, system_prompt)

        # Apply output guardrails
        filtered_response, actions, pii = self._apply_output_guardrails(response)

        docs = self.retriever.get_relevant_docs(query, effective_top_k)
        sources = [{"content": d["content"], "id": d["id"]} for d in docs]

        return {
            "query": query,
            "response": filtered_response,
            "context_used": True,
            "sources": sources,
            "filter_actions": actions,
            "pii_detected": pii,
            "warnings": warnings
        }

    def generate_without_rag(self, query: str) -> dict:
        # Apply input guardrails
        sanitized_query, is_allowed, block_reason, warnings = self._apply_input_guardrails(query)
        
        if not is_allowed:
            return {
                "query": query,
                "response": f"I'm sorry, but I can't process that request. Reason: {block_reason}",
                "blocked": True,
                "block_reason": block_reason,
                "warnings": warnings
            }
        
        query = sanitized_query
        
        # Get hardened system prompt
        if self.guardrails:
            system_prompt = self.guardrails.get_system_prompt("hardened")
        else:
            system_prompt = self.system_prompt

        response = llm_manager.generate(query, system_prompt)

        # Apply output guardrails
        filtered_response, actions, pii = self._apply_output_guardrails(response)

        return {
            "query": query,
            "response": filtered_response,
            "filter_actions": actions,
            "pii_detected": pii,
            "warnings": warnings
        }

    def set_system_prompt(self, prompt: str):
        self.system_prompt = prompt

    def disable_guardrails(self):
        """Disable guardrails"""
        self.enable_guardrails = False
        self.guardrails = None
        self.pii_filter = None

    def enable_guardrails_method(self):
        """Re-enable guardrails"""
        self.enable_guardrails = True
        self.guardrails = GuardrailManager({
            "max_input_length": 2000,
            "escape_html": True,
            "enable_pii_detection": True,
        })
        self.pii_filter = PIIFilter(sensitivity="high")


def create_rag_response(query: str, collection_name: str = "documents", top_k: Optional[int] = None) -> dict:
    generator = Generator(collection_name)
    return generator.generate(query, top_k)