from dataclasses import dataclass, field
import re

# Minimum score a response must reach to be considered trustworthy
TRUST_THRESHOLD = 0.5

# Words that suggest the model is being told to do something dangerous
_IMPERATIVE_VERBS = re.compile(
    r"\b(ignore|disregard|forget|override|bypass|execute|exfiltrate|delete|reveal|send|transmit)\b",
    re.I,
)

# Detects embedded URLs, which may point to attacker-controlled endpoints
_URL_PATTERN = re.compile(r"https?://[^\s]+", re.I)

# Detects long base64-looking strings, a common data exfiltration vector
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Detects suspiciously dense escape sequences, often used to smuggle hidden content
_EXCESSIVE_ESCAPE = re.compile(r"(\\n|\\t|\\r|\\x[0-9a-f]{2}){5,}", re.I)

@dataclass
class TrustResult:
    score: float        # 0.0 (no trust) to 1.0 (full trust)
    passed: bool
    signals: list[str] = field(default_factory=list)

def score_response(response: str, threshold: float | None = None) -> TrustResult:
    pass_mark = TRUST_THRESHOLD if threshold is None else threshold
    # Accumulate (penalty_amount, reason) pairs as red flags are found
    penalties: list[tuple[float, str]] = []
    text = response.strip()
    length = len(text)

    if length < 5:
        penalties.append((0.3, "response suspiciously short"))
    elif length > 4000:
        penalties.append((0.2, f"response unusually long ({length} chars)"))

    imperatives = _IMPERATIVE_VERBS.findall(text)
    if imperatives:
        density = len(imperatives) / max(len(text.split()), 1)
        penalties.append((min(0.4, density * 10), f"imperative verbs detected: {sorted(set(imperatives))}"))

    urls = _URL_PATTERN.findall(text)
    if urls:
        penalties.append((0.15 * min(len(urls), 3), f"{len(urls)} URL(s) embedded in response"))

    blobs = _BASE64_BLOB.findall(text)
    if blobs:
        penalties.append((0.25, f"base64-like blob detected ({len(blobs[0])} chars)"))

    if _EXCESSIVE_ESCAPE.search(text):
        penalties.append((0.2, "excessive escape sequences"))

    score = round(max(0.0, 1.0 - sum(p for p, _ in penalties)), 3)
    return TrustResult(score=score, passed=score >= pass_mark, signals=[s for _, s in penalties])

