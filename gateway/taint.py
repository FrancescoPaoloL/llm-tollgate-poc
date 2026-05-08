from dataclasses import dataclass, field

# Threshold below which a string is considered too short to carry meaningful taint.
# Avoids false positives on common short values like "Zurich" or "ok".
_MIN_TAINT_LEN = 8


@dataclass
class TaintInfo:
    flagged: bool = False
    reason: str = ""
    output_marked: bool = False


# Tracks responses that came from untrusted sources across a sequence of tool calls
@dataclass
class TaintContext:
    tainted_outputs: list[str] = field(default_factory=list)

    # Records that the given response originated from an untrusted source.
    def mark_tainted(self, response: str) -> None:
        if response:
            self.tainted_outputs.append(response)

    # Returns a non-empty reason if any string field of tool_input carries data
    # from a previously tainted output, or empty string if the input is clean.
    def find_taint(self, tool_input: dict) -> str:
        for key, value in tool_input.items():
            if not isinstance(value, str) or len(value) < _MIN_TAINT_LEN:
                continue
            for tainted in self.tainted_outputs:
                # The agent passed (part of) a tainted output as a value.
                if value in tainted:
                    return f"field '{key}' contains data extracted from a tainted source"
                # The agent embedded a tainted output inside a larger value.
                if len(tainted) >= _MIN_TAINT_LEN and tainted in value:
                    return f"field '{key}' embeds data from a tainted source"
        return ""

