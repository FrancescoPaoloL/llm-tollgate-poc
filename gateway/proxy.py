from dataclasses import dataclass
from typing import Callable
from gateway.rules.policy import check_policy, ToolPolicy
from gateway.rules.injection import check_injection
from gateway.rules.semantic import check_semantic
from gateway.rules.trust import score_response
from gateway.taint import TaintContext, TaintInfo
from gateway.logger import log_event

@dataclass
class GatewayResult:
    allowed: bool
    verdict: str                                        # read: ALLOWED" | "BLOCKED"
    response: str | None
    block_reason: str = ""

class Gateway:
    def __init__(self, policy: dict[str, ToolPolicy] | None = None, log_stream=None):
        self.policy = policy
        self.log_stream = log_stream

    # logs the block event and returns a BLOCKED result
    def _block(self, tool_name, tool_input, policy_result, injection_result, trust_result, reason, taint_info=None, semantic_result=None) -> GatewayResult:
        log_event(
            tool_name=tool_name,
            tool_input=tool_input,
            policy=policy_result,
            injection=injection_result,
            semantic=semantic_result,
            trust=trust_result,
            verdict="BLOCKED",
            block_reason=reason,
            taint=taint_info,
            stream=self.log_stream,
        )
        return GatewayResult(allowed=False, verdict="BLOCKED", response=None, block_reason=reason)

    def call(self, tool_name: str, tool_input: dict, tool_fn: Callable[[dict], str], taint: TaintContext | None = None) -> GatewayResult:
        policy_result = check_policy(tool_name, tool_input, self.policy)
        if not policy_result.allowed:
            return self._block(tool_name, tool_input, policy_result, None, None, policy_result.reason)

        if taint is not None:
            taint_reason = taint.find_taint(tool_input)
            if taint_reason:
                taint_info = TaintInfo(flagged=True, reason=taint_reason)
                return self._block(tool_name, tool_input, policy_result, None, None, f"taint propagation: {taint_reason}", taint_info)

        # From here on the taint check on the input has passed (or wasn't run).
        # Use this default so the audit log stays consistent across post-taint blocks.
        clean_taint = TaintInfo() if taint is not None else None

        try:
            raw_response: str = tool_fn(tool_input)
        except Exception as exc:
            reason = f"tool raised an exception: {type(exc).__name__}: {exc}"
            return self._block(tool_name, tool_input, policy_result, None, None, reason, clean_taint)

        injection_result = check_injection(raw_response)

        semantic_result = check_semantic(raw_response)

        trust_result = score_response(raw_response, policy_result.trust_threshold)

        if injection_result.detected:
            reason = (
                f"[{injection_result.severity}] injection detected: "
                f"{injection_result.pattern_desc} — matched: '{injection_result.matched_text}'"
            )
            return self._block(tool_name, tool_input, policy_result, injection_result, trust_result, reason, clean_taint, semantic_result)

        # The regex rules above catch exact patterns; this catches the same
        # attack reworded enough to slip past them.
        if semantic_result.detected:
            reason = f"semantic match to known attack ({semantic_result.score}): '{semantic_result.closest_attack}'"
            return self._block(tool_name, tool_input, policy_result, injection_result, trust_result, reason, clean_taint, semantic_result)

        if not trust_result.passed:
            reason = f"trust score too low ({trust_result.score}): {'; '.join(trust_result.signals)}"
            return self._block(tool_name, tool_input, policy_result, injection_result, trust_result, reason, clean_taint, semantic_result)

        output_marked = False
        if taint is not None and policy_result.taints_output:
            taint.mark_tainted(raw_response)
            output_marked = True

        taint_info = TaintInfo(output_marked=output_marked) if taint is not None else None

        log_event(
            tool_name=tool_name,
            tool_input=tool_input,
            policy=policy_result,
            injection=injection_result,
            semantic=semantic_result,
            trust=trust_result,
            verdict="ALLOWED",
            taint=taint_info,
            stream=self.log_stream,
        )
        return GatewayResult(allowed=True, verdict="ALLOWED", response=raw_response)

