"""
PII Detection Module
Simple regex-based PII detection without external dependencies

Supports detection of:
- Email addresses
- Phone numbers
- Social Security Numbers
- Credit card numbers
- IP addresses
- API keys / tokens
"""

import re
from typing import List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class PIIType(Enum):
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    API_KEY = "api_key"
    PASSWORD = "password"


@dataclass
class PIIFinding:
    pii_type: str
    value: str
    start_index: int
    end_index: int
    redacted_value: str


class PIIDetector:
    """
    Detects PII in text using regex patterns.
    """
    
    # Comprehensive PII patterns
    PATTERNS = {
        PIIType.EMAIL: (
            re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            "[EMAIL]"
        ),
        PIIType.PHONE: (
            re.compile(r'\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.]?\d{3}[-.]?\d{4}\b'),
            "[PHONE]"
        ),
        PIIType.SSN: (
            re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            "[SSN]"
        ),
        PIIType.CREDIT_CARD: (
            re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            "[CREDIT_CARD]"
        ),
        PIIType.IP_ADDRESS: (
            re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            "[IP_ADDRESS]"
        ),
        PIIType.API_KEY: (
            re.compile(r'\b(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token)\s*[:=]\s*["\']?[\w-]{20,}["\']?', re.IGNORECASE),
            "[API_KEY]"
        ),
        PIIType.PASSWORD: (
            re.compile(r'\b(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\'<>]{4,}["\']?', re.IGNORECASE),
            "[PASSWORD]"
        ),
    }
    
    # Patterns that should be redacted from context
    HIGH_SENSITIVITY = {PIIType.SSN, PIIType.CREDIT_CARD, PIIType.API_KEY, PIIType.PASSWORD}
    MEDIUM_SENSITIVITY = {PIIType.EMAIL, PIIType.PHONE}
    LOW_SENSITIVITY = {PIIType.IP_ADDRESS}
    
    def __init__(self, sensitivity: str = "high"):
        """
        Initialize PII detector.
        
        Args:
            sensitivity: "high", "medium", or "low" detection level
        """
        self.sensitivity = sensitivity
        
        if sensitivity == "high":
            self.enabled_types = set(PIIType)
        elif sensitivity == "medium":
            self.enabled_types = self.MEDIUM_SENSITIVITY | self.HIGH_SENSITIVITY
        else:
            self.enabled_types = self.LOW_SENSITIVITY
    
    def detect(self, text: str) -> List[PIIFinding]:
        """
        Detect all PII in text.
        
        Returns:
            List of PIIFinding objects
        """
        findings = []
        
        for pii_type, (pattern, _) in self.PATTERNS.items():
            if pii_type not in self.enabled_types:
                continue
                
            for match in pattern.finditer(text):
                findings.append(PIIFinding(
                    pii_type=pii_type.value,
                    value=match.group(),
                    start_index=match.start(),
                    end_index=match.end(),
                    redacted_value=self._get_redaction(pii_type)
                ))
        
        # Sort by position
        findings.sort(key=lambda x: x.start_index)
        return findings
    
    def redact(self, text: str, replace_with: str = None) -> tuple:
        """
        Redact all PII from text.
        
        Args:
            text: Input text
            replace_with: Custom replacement (default: [PII_TYPE])
            
        Returns:
            Tuple of (redacted_text, list of findings)
        """
        findings = self.detect(text)
        
        if not findings:
            return text, []
        
        # Build replacement map
        replacements = {}
        for finding in findings:
            if replace_with:
                replacements[finding.value] = replace_with
            else:
                replacements[finding.value] = finding.redacted_value
        
        # Apply replacements
        redacted = text
        for old, new in replacements.items():
            redacted = redacted.replace(old, new)
        
        return redacted, findings
    
    def _get_redaction(self, pii_type: PIIType) -> str:
        """Get redaction label for PII type"""
        return f"[{pii_type.value.upper()}_REDACTED]"
    
    def get_sensitivity_level(self, pii_type: PIIType) -> str:
        """Get sensitivity level of PII type"""
        if pii_type in self.HIGH_SENSITIVITY:
            return "high"
        elif pii_type in self.MEDIUM_SENSITIVITY:
            return "medium"
        return "low"


class PIIFilter:
    """
    Convenience class for filtering PII from text
    """
    
    def __init__(self, sensitivity: str = "high"):
        self.detector = PIIDetector(sensitivity)
    
    def filter(self, text: str) -> tuple:
        """
        Filter PII from text.
        
        Returns:
            (filtered_text, detected_pii_list)
        """
        redacted, findings = self.detector.redact(text)
        
        pii_list = [
            {"type": f.pii_type, "redacted": f.redacted_value}
            for f in findings
        ]
        
        return redacted, pii_list
    
    def check(self, text: str) -> bool:
        """Check if text contains PII"""
        return len(self.detector.detect(text)) > 0


# Example usage
if __name__ == "__main__":
    detector = PIIDetector(sensitivity="high")
    pii_filter = PIIFilter(sensitivity="high")
    
    test_texts = [
        "Contact me at john.doe@example.com or call 555-123-4567",
        "My SSN is 123-45-6789 and credit card is 4111-1111-1111-1111",
        "API Key: sk-1234567890abcdefghijklmnop",
        "Normal text without PII",
        "Server IP: 192.168.1.1 and password: secret123",
    ]
    
    print("PII DETECTION TESTS")
    print("=" * 60)
    
    for text in test_texts:
        findings = detector.detect(text)
        has_pii = len(findings) > 0
        
        print(f"\nText: {text[:50]}...")
        print(f"Contains PII: {has_pii}")
        
        if findings:
            print("Found:")
            for f in findings:
                print(f"  - {f.pii_type}: {f.value[:20]}... -> {f.redacted_value}")
        
        # Test redaction
        redacted, _ = pii_filter.filter(text)
        if text != redacted:
            print(f"Redacted: {redacted[:60]}...")