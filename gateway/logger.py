import json
import hashlib
import sys
from datetime import datetime, timezone
from typing import IO
from gateway.rules.policy import PolicyResult
from gateway.rules.injection import InjectionResult
from gateway.rules.semantic import SemanticResult
from gateway.rules.trust import TrustResult
from gateway.taint import TaintInfo

def _hash_input(tool_input: dict) -> str:
    raw = json.dumps(tool_input, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def log_event(
    tool_name: str,
    tool_input: dict,
    policy: PolicyResult,
    injection: InjectionResult | None,
    semantic: SemanticResult | None,
    trust: TrustResult | None,
    verdict: str,
    block_reason: str = "",
    taint: TaintInfo | None = None,
    stream: IO[str] | None = None,
) -> None:
    event = {
        "ts":         datetime.now(timezone.utc).isoformat(),
        "tool":       tool_name,
        "input_hash": _hash_input(tool_input),
        "policy":     {"allowed": policy.allowed, "reason": policy.reason},
        "injection":  None if injection is None else {
            "detected":     injection.detected,
            "severity":     injection.severity,
            "pattern":      injection.pattern_desc,
            "matched_text": injection.matched_text,
        },
        "semantic":   None if semantic is None else {
            "detected":       semantic.detected,
            "score":          semantic.score,
            "closest_attack": semantic.closest_attack,
        },
        "trust":      None if trust is None else {
            "score":   trust.score,
            "passed":  trust.passed,
            "signals": trust.signals,
        },
        "taint":      None if taint is None else {
            "flagged":       taint.flagged,
            "reason":        taint.reason,
            "output_marked": taint.output_marked,
        },
        "verdict":      verdict,
        "block_reason": block_reason,
    }
    print(json.dumps(event), file=stream or sys.stdout)

