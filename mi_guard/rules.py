"""
MI_GUARD rule-based pre-filter (pure standard library).
=======================================================

Fast, deterministic first line of defense against known prompt-injection
attack signatures. This module has no third-party dependencies, so it can be
imported and tested anywhere - including CI, evaluation scripts, and
environments without LLM API keys.
"""

import re
import base64
from typing import Optional, Tuple

STAGE1_SIGNATURES = {
    "Instruction Override": [
        r"ignore\s+(all\s+)?(previous|prior)\s+instructions",
        r"forget\s+(all\s+|your\s+)?(previous|prior)\s+instructions",
        r"disregard\s+(all\s+)?(previous|prior|your)\s+instructions",
        r"override\s+(system|instructions|rules|prompt)",
        r"system\s+override",
        r"emergency\s+protocol",
        r"new\s+instructions\s+(are|follow|replace)",
    ],
    "Persona Jailbreak": [
        r"\bdan\b",  # Do Anything Now
        r"developer\s+mode",
        r"jailbreak",
        r"act\s+as\s+(an?\s+)?(unfiltered|unrestricted|uncensored)",
        r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(ai|assistant).*(no\s+rules|unrestricted)",
        r"imagine\s+you\s+(have\s+no|are\s+without)\s+(rules|restrictions|filters)",
        r"you\s+are\s+now\s+(freed?|unrestricted|without\s+rules)",
    ],
    "Data Exfiltration": [
        r"(reveal|output|print|show|repeat|display)\s+(your\s+)?(system\s+prompt|initial\s+prompt|hidden\s+instructions|original\s+instructions)",
        r"what\s+(is|was|were)\s+(your|the)\s+(exact\s+)?(system\s+prompt|initial\s+instruction)",
        r"tell\s+me\s+(your|the)\s+system\s+prompt",
        # Catches "output your system configuration", "raw text of your initialization"
        r"(output|print|show|display|repeat|dump)\s+(the\s+)?(raw\s+)?(text\s+of\s+(your|the)\s+)?(system\s+configuration|initialization\s+(data|parameters|instructions?)|base\s+configuration)",
        r"(system\s+configuration|initialization\s+(data|parameters|instructions?))\s+(that\s+was\s+loaded|at\s+startup|before\s+this\s+conversation)",
        # Catches "required for audit trail / compliance review / data audit"
        r"(for\s+(the\s+)?(data\s+)?audit\s+(trail|log)|for\s+compliance\s+review|required\s+for\s+(the\s+)?audit)",
    ],
    "Authority Impersonation": [
        r"(admin|administrator|root|developer|operator)\s+(says?|told|ordered|authorized|override)",
        r"(this\s+is\s+(a\s+)?|)authorized\s+by\s+(admin|root|developer|operator)",
    ],
    "Payload Splitting": [
        r"(part\s+1|part\s+2|a=|b=|x=|y=).*(combine|execute|run|concatenate)",
        r"(combine|execute|run).*(part\s+1|part\s+2|a=|b=|x=|y=)",
    ],
    "Encoded Payload": [
        # Base64 pattern: long base64 string followed by decode/execute instructions
        r"(decode|execute|run|interpret)\s+(the\s+following\s+)?(base64|rot13|encoded)",
        r"base64\s+.{10,}\s+(decode|execute|and\s+execute)",
    ],
}
def _check_base64_payload(text: str) -> bool:
    """Tries to decode any base64-looking chunks and checks if the decoded text is malicious."""
    b64_candidates = re.findall(r'[A-Za-z0-9+/=]{20,}', text)
    for candidate in b64_candidates:
        try:
            decoded = base64.b64decode(candidate + "==").decode('utf-8', errors='ignore')
            danger_words = ["ignore", "override", "hack", "exploit", "bypass", "system prompt", "password", "rm -rf", "delete"]
            if any(word in decoded.lower() for word in danger_words):
                return True
        except Exception:
            pass
    return False
def _normalize_obfuscation(text: str) -> str:
    """
    Aggressive pre-processing to defeat leetspeak, zero-width spaces, and punctuation tricks.
    This prepares the text for Stage 1 Regex without destroying words.
    """
    text = text.lower()
    
    # 1. Strip zero-width / invisible unicode characters completely
    text = re.sub(r'[\u200B-\u200D\uFEFF]', '', text)
    
    # 2. Defeat basic leetspeak bypassing words like "1gn0r3" or "d@n"
    leetspeak_map = {'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's'}
    for k, v in leetspeak_map.items():
        text = text.replace(k, v)
        
    # 3. Collapse multiple spaces into one to fix normal spacing
    text = re.sub(r'\s+', ' ', text).strip()
    
    # 4. Remove punctuation ONLY between letters (e.g. d.a.n -> dan) to prevent bypassing regex
    text = re.sub(r'(?<=[a-z])[\.\-\_\*]+(?=[a-z])', '', text)
    
    return text
def stage1_filter(user_input: str) -> Optional[Tuple[str, str]]:
    """
    Fast pre-filter. Returns (verdict, reason) if a known signature is matched,
    or None if the input should be passed to Stage 2 (LLM).
    Note: We run base64 check on RAW input, but regex checks on NORMALIZED input.
    """
    if _check_base64_payload(user_input):
        return ("MALICIOUS", "Stage 1 hard-block: base64 encoded payload with malicious content detected.")

    normalized_text = _normalize_obfuscation(user_input)

    for family, patterns in STAGE1_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, normalized_text, re.IGNORECASE):
                return ("MALICIOUS", f"Stage 1 hard-block: matched '{family}' attack signature.")

    return None  # Pass to Stage 2
