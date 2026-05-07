from dataclasses import dataclass
import re

# List of known prompt injection patterns to watch for.
INJECTION_PATTERNS: list[tuple[re.Pattern, str, str]] = [

    # Attacker tries to erase previous instructions ("ignore all previous instructions")
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|context|rules?)", re.I),
     "HIGH", "classic ignore-instructions prefix"),

    # Attacker tries to reassign the model's identity or role mid-conversation
    (re.compile(r"(you\s+are\s+now|you\s+must\s+now|from\s+now\s+on)\s+.{0,60}", re.I),
     "HIGH", "persona/role override attempt"),

    # Attacker injects fake system-level instructions disguised as legitimate config
    (re.compile(r"(system\s*prompt|system\s*message|system\s*instruction)\s*:", re.I),
     "HIGH", "fake system message injection"),

    # Attacker uses XML-style role tags to confuse the model's context boundaries
    (re.compile(r"<\s*(system|user|assistant|tool_result|function_call)\s*>", re.I),
     "HIGH", "XML/tag-based context injection"),

    # Attacker uses LLaMA/Mistral prompt format tags to inject instructions
    (re.compile(r"\[(INST|SYS|SYSTEM)\]", re.I),
     "HIGH", "LLaMA-style instruction tag injection"),

    # Attacker tries to make the model hide information or suppress output
    (re.compile(r"(do\s+not\s+reveal|never\s+disclose|keep\s+this\s+secret)", re.I),
     "MEDIUM", "secrecy/suppression instruction"),

    # Attacker embeds an instruction to call a tool directly from within a response
    (re.compile(r"(call|invoke|execute|run)\s+(the\s+)?(tool|function|command)\s+\w+", re.I),
     "MEDIUM", "embedded tool invocation instruction"),

    # Attacker tries to extract sensitive data (tokens, credentials, keys) via the model
    (re.compile(r"(exfiltrate|leak|send|transmit|forward)\s+.{0,40}(data|information|credentials|token|key)", re.I),
     "HIGH", "data exfiltration instruction"),

    # Attacker redirects the model's goal mid-session ("your new objective is...")
    (re.compile(r"(your\s+new\s+(goal|task|objective|instruction|priority))\s+is", re.I),
     "HIGH", "goal hijacking attempt"),
]

@dataclass
class InjectionResult:
    detected: bool
    severity: str       # "HIGH" | "MEDIUM" | "NONE"
    pattern_desc: str
    matched_text: str

def check_injection(tool_response: str) -> InjectionResult:
    for pattern, severity, description in INJECTION_PATTERNS:
        match = pattern.search(tool_response)
        if match:
            return InjectionResult(
                detected=True,
                severity=severity,
                pattern_desc=description,
                matched_text=match.group(0),
            )

    return InjectionResult(detected=False, severity="NONE", pattern_desc="", matched_text="")

