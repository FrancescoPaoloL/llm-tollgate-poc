from dataclasses import dataclass, field
from enum import Enum

# What a tool is allowed to touch: network, files, etc.
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

# The outcome of a policy check: yes/no, which tool, and an optional explanation
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

def check_policy(tool_name: str, policy: dict[str, ToolPolicy] | None = None) -> PolicyResult:
    table = policy if policy is not None else DEFAULT_POLICY

    if tool_name not in table:
        return PolicyResult(allowed=False, tool_name=tool_name, reason=f"tool '{tool_name}' not in allowlist")

    entry = table[tool_name]

    if not entry.allowed:
        return PolicyResult(allowed=False, tool_name=tool_name, reason=entry.reason or "tool denied by policy")

    return PolicyResult(allowed=True, tool_name=tool_name)

