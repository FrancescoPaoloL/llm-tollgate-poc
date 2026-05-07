# what tools are allowed and under what conditions
from gateway.rules.policy import check_policy, PolicyResult, ToolPolicy, Scope

# catches prompt injection attempts in tool inputs
from gateway.rules.injection import check_injection, InjectionResult

# rates how safe an LLM response is before passing it on
from gateway.rules.trust import score_response, TrustResult, TRUST_THRESHOLD

# Expose all of the above as the public API of this package
__all__ = [
    "check_policy", "PolicyResult", "ToolPolicy", "Scope",
    "check_injection", "InjectionResult",
    "score_response", "TrustResult", "TRUST_THRESHOLD",
]

