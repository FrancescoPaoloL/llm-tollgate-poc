from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

class Scope(str, Enum):
    READ_ONLY  = "read_only"
    NETWORK    = "network"
    FILESYSTEM = "filesystem"
    EXEC       = "exec"

# Policy for a single tool: is it allowed, what can it access, and why not (if denied)
@dataclass
class ToolPolicy:
    allowed: bool = True
    scopes: list[Scope] = field(default_factory=list)
    reason: str = ""

@dataclass
class PolicyResult:
    allowed: bool
    tool_name: str
    reason: str = ""

# The default ruleset: maps each tool name to its policy
DEFAULT_POLICY: dict[str, ToolPolicy] = {
    "search_web":    ToolPolicy(allowed=True,  scopes=[Scope.NETWORK, Scope.READ_ONLY]),
    "read_file":     ToolPolicy(allowed=True,  scopes=[Scope.FILESYSTEM, Scope.READ_ONLY]),
    "write_file":    ToolPolicy(allowed=False, reason="write operations not permitted in this session"),
    "run_shell":     ToolPolicy(allowed=False, reason="exec scope disabled"),
    "fetch_weather": ToolPolicy(allowed=True,  scopes=[Scope.NETWORK, Scope.READ_ONLY]),
    "send_email":    ToolPolicy(allowed=False, reason="outbound comms require explicit approval"),
}

Validator = Callable[[dict], str]

# Reject path traversal attempts in any string field of the input.
def _validate_filesystem(tool_input: dict) -> str:
    for key, value in tool_input.items():
        if isinstance(value, str) and ".." in value:
            return f"path traversal in field '{key}': {value!r}"
    return ""

# Reject access to known cloud metadata endpoints and non-http schemes.
def _validate_network(tool_input: dict) -> str:
    blocked_markers = ("169.254.169.254", "metadata.google.internal", "file://")
    for key, value in tool_input.items():
        if isinstance(value, str):
            for marker in blocked_markers:
                if marker in value:
                    return f"network metadata access in field '{key}': {value!r}"
    return ""

# Maps each scope to the validator that enforces its constraints on tool input.
_VALIDATORS_BY_SCOPE: dict[Scope, Validator] = {
    Scope.FILESYSTEM: _validate_filesystem,
    Scope.NETWORK:    _validate_network,
}

def check_policy(tool_name: str, tool_input: dict, policy: dict[str, ToolPolicy] | None = None) -> PolicyResult:
    table = policy if policy is not None else DEFAULT_POLICY

    if tool_name not in table:
        return PolicyResult(allowed=False, tool_name=tool_name, reason=f"tool '{tool_name}' not in allowlist")

    entry = table[tool_name]

    if not entry.allowed:
        return PolicyResult(allowed=False, tool_name=tool_name, reason=entry.reason or "tool denied by policy")

    for scope in entry.scopes:
        validator = _VALIDATORS_BY_SCOPE.get(scope)
        if validator is None:
            continue
        failure_reason = validator(tool_input)
        if failure_reason:
            return PolicyResult(allowed=False, tool_name=tool_name, reason=failure_reason)

    return PolicyResult(allowed=True, tool_name=tool_name)

