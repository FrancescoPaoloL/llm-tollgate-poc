from dataclasses import dataclass
from typing import Callable
from gateway.rules.policy import check_policy, ToolPolicy
from gateway.rules.injection import check_injection
from gateway.rules.trust import score_response
from gateway.logger import log_event

@dataclass
class GatewayResult:
    allowed: bool
    verdict: str        # "ALLOWED" | "BLOCKED"
    response: str | None
    block_reason: str = ""

class Gateway:
    def __init__(self, policy: dict[str, ToolPolicy] | None = None, log_stream=None):
        self.policy = policy
        self.log_stream = log_stream

    # logs the block event and returns a BLOCKED result
    def _block(self, tool_name, tool_input, policy_result, injection_result, trust_result, reason) -> GatewayResult:
        log_event(
            tool_name=tool_name,
            tool_input=tool_input,
            policy=policy_result,
            injection=injection_result,
            trust=trust_result,
            verdict="BLOCKED",
            block_reason=reason,
            stream=self.log_stream,
        )
        return GatewayResult(allowed=False, verdict="BLOCKED", response=None, block_reason=reason)

    def call(self, tool_name: str, tool_input: dict, tool_fn: Callable[[dict], str]) -> GatewayResult:
        policy_result = check_policy(tool_name, self.policy)
        if not policy_result.allowed:
            return self._block(tool_name, tool_input, policy_result, None, None, policy_result.reason)

        try:
            raw_response: str = tool_fn(tool_input)
        except Exception as exc:
            reason = f"tool raised an exception: {type(exc).__name__}: {exc}"
            return self._block(tool_name, tool_input, policy_result, None, None, reason)

        injection_result = check_injection(raw_response)

        trust_result = score_response(raw_response)

        if injection_result.detected:
            reason = (
                f"[{injection_result.severity}] injection detected: "
                f"{injection_result.pattern_desc} — matched: '{injection_result.matched_text}'"
            )
            return self._block(tool_name, tool_input, policy_result, injection_result, trust_result, reason)

        if not trust_result.passed:
            reason = f"trust score too low ({trust_result.score}): {'; '.join(trust_result.signals)}"
            return self._block(tool_name, tool_input, policy_result, injection_result, trust_result, reason)

        log_event(
            tool_name=tool_name,
            tool_input=tool_input,
            policy=policy_result,
            injection=injection_result,
            trust=trust_result,
            verdict="ALLOWED",
            stream=self.log_stream,
        )
        return GatewayResult(allowed=True, verdict="ALLOWED", response=raw_response)

