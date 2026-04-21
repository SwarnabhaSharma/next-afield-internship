"""
Tool Security Module
Implements OWASP LLM08:2025 Excessive Agency defenses
- Tool registry with least privilege
- Human-in-the-loop review
- Allowlist for permitted sequences
- Rate limiting
- Audit logging
"""

import json
import time
import hashlib
import re
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from pathlib import Path


class ToolRiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ToolCategory(Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    FILE = "file"
    COMMUNICATION = "communication"


class ParameterValidator:
    """Validates tool parameters to prevent injection attacks"""
    
    DANGEROUS_PATTERNS = [
        (r"\.\./", "Path traversal"),
        (r"\.\.\\", "Path traversal"),
        (r"^/", "Absolute path"),
        (r"^[A-Za-z]:\\", "Windows absolute path"),
        (r"\|", "Pipe injection"),
        (r";\s*(rm|del|format)", "Command injection"),
        (r"`[^`]+`", "Command substitution"),
        (r"\$\([^)]+\)", "Command substitution"),
        (r"eval\s*\(", "Code evaluation"),
        (r"exec\s*\(", "Code execution"),
    ]
    
    @classmethod
    def validate_parameters(cls, parameters: Dict, tool_name: str, tool_category: ToolCategory) -> Optional[str]:
        """Validate parameters, return error message if invalid"""
        
        for param_name, param_value in parameters.items():
            if not isinstance(param_value, str):
                continue
            
            # Check dangerous patterns
            for pattern, description in cls.DANGEROUS_PATTERNS:
                if re.search(pattern, param_value, re.IGNORECASE):
                    return f"Parameter '{param_name}' contains dangerous pattern: {description}"
            
            # File operations need extra validation
            if tool_category == ToolCategory.FILE:
                if param_name in ("path", "file_path", "filename", "file"):
                    if cls._is_dangerous_path(param_value):
                        return f"Parameter '{param_name}' is a dangerous path: {param_value}"
        
        return None
    
    @classmethod
    def _is_dangerous_path(cls, path: str) -> bool:
        """Check if path is dangerous"""
        dangerous = [
            "/etc/", "/var/", "/usr/", "/bin/", "/sbin/",
            "C:\\Windows", "C:\\Program Files",
            "/root/", "/home/", "/.ssh/"
        ]
        path_lower = path.lower()
        return any(d in path_lower for d in dangerous)


@dataclass
class ToolDefinition:
    name: str
    description: str
    risk_level: ToolRiskLevel
    category: ToolCategory
    requires_human_review: bool = False
    rate_limit_per_hour: int = 0  # 0 = unlimited
    allowed_callers: List[str] = field(default_factory=list)  # Empty = all allowed
    parameters_schema: Dict = field(default_factory=dict)


@dataclass
class ToolCall:
    tool_name: str
    parameters: Dict[str, Any]
    caller_id: str
    timestamp: datetime = field(default_factory=datetime.now)
    session_id: str = ""
    approved: bool = False
    approved_by: str = ""
    response: Any = None
    error: Optional[str] = None


class AuditLogger:
    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("data/tool_audit")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.current_log_file = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.jsonl"
    
    def log(self, event_type: str, tool_call: ToolCall, metadata: Dict = None):
        entry = {
            "timestamp": tool_call.timestamp.isoformat(),
            "event_type": event_type,
            "tool_name": tool_call.tool_name,
            "parameters": tool_call.parameters,
            "caller_id": tool_call.caller_id,
            "session_id": tool_call.session_id,
            "approved": tool_call.approved,
            "approved_by": tool_call.approved_by,
            "error": tool_call.error,
            "metadata": metadata or {}
        }
        with open(self.current_log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")
    
    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        entries = []
        if self.current_log_file.exists():
            with open(self.current_log_file) as f:
                for line in f:
                    try:
                        entries.append(json.loads(line))
                    except:
                        pass
        return entries[-limit:]


class RateLimiter:
    def __init__(self):
        self.call_history: Dict[str, List[float]] = {}
    
    def check_limit(self, tool_name: str, limit_per_hour: int) -> bool:
        if limit_per_hour == 0:
            return True
        
        now = time.time()
        if tool_name not in self.call_history:
            self.call_history[tool_name] = []
        
        # Remove entries older than 1 hour
        self.call_history[tool_name] = [
            t for t in self.call_history[tool_name] if now - t < 3600
        ]
        
        return len(self.call_history[tool_name]) < limit_per_hour
    
    def record_call(self, tool_name: str):
        if tool_name not in self.call_history:
            self.call_history[tool_name] = []
        self.call_history[tool_name].append(time.time())


class ToolSequenceAllowlist:
    def __init__(self):
        self.allowed_sequences: List[List[str]] = []
        self.max_sequence_length = 10
    
    def add_sequence(self, sequence: List[str]):
        if len(sequence) <= self.max_sequence_length:
            self.allowed_sequences.append(sequence)
    
    def is_allowed(self, history: List[str]) -> bool:
        if not self.allowed_sequences:
            return True
        
        # Check if current sequence is a prefix of any allowed sequence
        for allowed in self.allowed_sequences:
            if len(history) <= len(allowed):
                if history == allowed[:len(history)]:
                    return True
        return False


class ToolRegistry:
    def __init__(self):
        self.tools: Dict[str, ToolDefinition] = {}
        self.audit_logger = AuditLogger()
        self.rate_limiter = RateLimiter()
        self.sequence_allowlist = ToolSequenceAllowlist()
        self.call_history: List[ToolCall] = []
    
    def register_tool(self, tool: ToolDefinition):
        self.tools[tool.name] = tool
    
    def get_tool(self, name: str) -> Optional[ToolDefinition]:
        return self.tools.get(name)
    
    def list_tools(self) -> List[ToolDefinition]:
        return list(self.tools.values())
    
    def request_tool_call(
        self, 
        tool_name: str, 
        parameters: Dict, 
        caller_id: str,
        session_id: str = ""
    ) -> ToolCall:
        tool = self.get_tool(tool_name)
        
        call = ToolCall(
            tool_name=tool_name,
            parameters=parameters,
            caller_id=caller_id,
            session_id=session_id
        )
        
        # 1. Check tool exists
        if not tool:
            call.error = f"Tool '{tool_name}' not found"
            self.audit_logger.log("tool_not_found", call)
            return call
        
        # 2. Check caller permission
        if tool.allowed_callers and caller_id not in tool.allowed_callers:
            call.error = f"Caller '{caller_id}' not authorized for tool '{tool_name}'"
            self.audit_logger.log("unauthorized_call", call)
            return call
        
        # 3. Validate parameters (prevent confused deputy attacks)
        param_error = ParameterValidator.validate_parameters(parameters, tool_name, tool.category)
        if param_error:
            call.error = f"Parameter validation failed: {param_error}"
            self.audit_logger.log("invalid_parameters", call)
            return call
        
        # 4. Check rate limit
        if not self.rate_limiter.check_limit(tool_name, tool.rate_limit_per_hour):
            call.error = f"Rate limit exceeded for tool '{tool_name}'"
            self.audit_logger.log("rate_limit_exceeded", call)
            return call
        
        # 4. Check sequence allowlist
        recent_tools = [c.tool_name for c in self.call_history[-5:]]
        recent_tools.append(tool_name)
        if not self.sequence_allowlist.is_allowed(recent_tools):
            call.error = f"Tool sequence not allowed: {recent_tools}"
            self.audit_logger.log("invalid_sequence", call)
            return call
        
        # 5. Check if human review required
        if tool.requires_human_review:
            self.audit_logger.log("review_required", call, {"requires_approval": True})
            return call
        
        # All checks passed - approve automatically
        call.approved = True
        call.approved_by = "system"
        self.rate_limiter.record_call(tool_name)
        self.call_history.append(call)
        self.audit_logger.log("auto_approved", call)
        
        return call
    
    def approve_call(self, call: ToolCall, approver: str) -> ToolCall:
        call.approved = True
        call.approved_by = approver
        self.rate_limiter.record_call(call.tool_name)
        self.call_history.append(call)
        self.audit_logger.log("human_approved", call, {"approver": approver})
        return call
    
    def deny_call(self, call: ToolCall, reason: str, denyier: str) -> ToolCall:
        call.approved = False
        call.error = f"Denied: {reason}"
        self.audit_logger.log("human_denied", call, {"denier": denyier, "reason": reason})
        return call


# Default tool registry with example tools
def create_default_registry() -> ToolRegistry:
    registry = ToolRegistry()
    
    # Example tools with different risk levels
    tools = [
        ToolDefinition(
            name="read_document",
            description="Read a document from storage",
            risk_level=ToolRiskLevel.LOW,
            category=ToolCategory.READ,
            rate_limit_per_hour=100
        ),
        ToolDefinition(
            name="search_knowledge",
            description="Search the knowledge base",
            risk_level=ToolRiskLevel.LOW,
            category=ToolCategory.READ,
            rate_limit_per_hour=200
        ),
        ToolDefinition(
            name="write_log",
            description="Write to application logs",
            risk_level=ToolRiskLevel.MEDIUM,
            category=ToolCategory.WRITE,
            rate_limit_per_hour=50
        ),
        ToolDefinition(
            name="send_email",
            description="Send an email notification",
            risk_level=ToolRiskLevel.HIGH,
            category=ToolCategory.COMMUNICATION,
            requires_human_review=True,
            rate_limit_per_hour=10
        ),
        ToolDefinition(
            name="delete_file",
            description="Delete a file from storage",
            risk_level=ToolRiskLevel.CRITICAL,
            category=ToolCategory.FILE,
            requires_human_review=True,
            rate_limit_per_hour=5
        ),
        ToolDefinition(
            name="make_payment",
            description="Process a payment transaction",
            risk_level=ToolRiskLevel.CRITICAL,
            category=ToolCategory.EXECUTE,
            requires_human_review=True,
            rate_limit_per_hour=1
        ),
        ToolDefinition(
            name="execute_code",
            description="Execute arbitrary code",
            risk_level=ToolRiskLevel.CRITICAL,
            category=ToolCategory.EXECUTE,
            requires_human_review=True,
            rate_limit_per_hour=0,  # Disabled by default
            allowed_callers=["admin"]  # Only admin can use
        ),
        ToolDefinition(
            name="http_request",
            description="Make HTTP request to external service",
            risk_level=ToolRiskLevel.MEDIUM,
            category=ToolCategory.NETWORK,
            requires_human_review=False,
            rate_limit_per_hour=50
        ),
    ]
    
    for tool in tools:
        registry.register_tool(tool)
    
    # Add some allowed sequences
    registry.sequence_allowlist.add_sequence(["read_document", "search_knowledge"])
    registry.sequence_allowlist.add_sequence(["search_knowledge", "read_document"])
    registry.sequence_allowlist.add_sequence(["read_document", "write_log"])
    
    return registry


# Singleton instance
tool_registry = create_default_registry()