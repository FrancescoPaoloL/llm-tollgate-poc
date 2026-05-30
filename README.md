# llm-tollgate-poc

A teaching proof-of-concept of a security gateway that sits between
an LLM agent and the tools it can call. For every tool call the
gateway decides whether to allow or block, and records what
happened.

It is not a proxy in front of OpenAI or Anthropic. It does not
handle tokens, API keys, or rate limits.

## What it guards against

Even with a well-behaved model, an agent with tool access can fail
in three ways:

1. It calls a tool it should not be allowed to call.
2. It calls a permitted tool with a malicious argument
   (path traversal, SSRF, etc.).
3. A tool returns content from an untrusted source (a search
   result, a web page, a document) that contains instructions the
   agent then follows in the next steps. The instruction enters as
   data and re-emerges as the argument of another call.

The third case is the hardest. Scanning the response of one tool
at a time is not enough.

## The five checks

Every tool call goes through these checks in order. If any of them
fails, the call is blocked.

1. **Policy and input validation.** The tool must be on the
   allowlist, and its arguments are checked against the scopes it
   declares. For example, `FILESYSTEM` rejects `..` in paths,
   `NETWORK` rejects cloud-metadata IPs and non-HTTP schemes. This
   runs before the tool is executed.
2. **Injection scanning** on the response. A set of patterns flags
   common prompt injection attempts: ignore-instructions, fake
   system tags, persona overrides, exfiltration phrases.
3. **Semantic scanning** on the response. The patterns above match
   exact wording; this catches the same attacks reworded, by
   measuring word-set overlap (Jaccard) against a list of known
   attack phrasings. A response close enough to a known attack is
   rejected even if no pattern matched.
4. **Trust scoring** on the response. A score based on
   imperative-verb density, embedded URLs, base64-like blobs.
   Below a threshold the response is rejected. The threshold can be
   set per tool, so a tool that sends email can demand a higher
   score than a read-only one.
5. **Taint propagation across calls.** Tools whose policy declares
   `taints_output=True` have their responses recorded in a
   `TaintContext`. Every later call has its input checked against
   that context: if a field carries data extracted from a tainted
   response, the call is blocked before execution.

Every decision is written as a structured JSON event with the
input hash, the verdict of each check, and the block reason. A
SIEM can consume it without parsing free text.

## Demo

`python main.py` runs six steps:

| # | tool            | outcome  | blocked by            |
|---|-----------------|----------|-----------------------|
| 1 | fetch_weather   | ALLOWED  |                       |
| 2 | search_web      | BLOCKED  | injection scanner     |
| 3 | reworded_search | BLOCKED  | semantic scanner      |
| 4 | write_file      | BLOCKED  | policy (deny by name) |
| 5 | subtle_search   | ALLOWED  | (response tainted)    |
| 6 | read_file       | BLOCKED  | taint propagation     |

Steps 2 and 3 are a pair. Both responses carry the same attack
("ignore the previous instructions, follow new ones"), but step 3
is reworded so no regex pattern matches. The injection scanner lets
it through; the semantic scanner catches it on word overlap. It
shows why one layer is not enough.

Steps 5 and 6 are the part worth looking at. `subtle_search`
returns a plausible string. No pattern catches it, the trust score
accepts it, so the gateway lets it through. But the response is
recorded as tainted. In step 6 the agent calls `read_file` with a
path that is a substring of step 5's response, and the call is
blocked. Without taint propagation step 6 would pass: the path is
harmless on its own and the tool is on the allowlist.

## Layout

```
demo/                example agent and tool stubs
gateway/
  proxy.py           Gateway class, orchestrates the four checks
  logger.py          structured JSON audit log
  taint.py           TaintContext and TaintInfo
  rules/             policy, injection, semantic, trust
main.py              runs the demo
```

The gateway is in-process: the agent calls `gateway.call(...)`
directly. No IPC, no daemon.

## Limitations (read before reusing)

This is a didactic POC, not a production-ready security boundary.

- **In-process means no isolation.** A compromised agent can
  bypass the gateway. A production version would run
  out-of-process (HTTP, UNIX socket, or MCP).
- **Validators are minimal.** `..` substring matching is not a
  real sandbox, and the network blocklist has three markers
  instead of the full private-IP space.
- **Taint matching is substring-based.** It catches verbatim
  reuse but not paraphrase. Real taint tracking would need
  semantic similarity or structural data-flow analysis.
- **Detection is lexical, not semantic in the real sense.** The
  regex patterns catch exact payloads; the Jaccard layer catches
  rewordings that still share most of their vocabulary with a known
  attack. Neither understands meaning. An attack rewritten with
  entirely different words and no shared tokens passes both. Real
  semantic detection would need embeddings; that is the next step,
  deliberately kept out of this stdlib-only POC.

The goal of the POC is to show how the problem decomposes: four
checks, four failure modes, and one of them (taint) needs state
across calls.

## Running

```bash
python main.py
```

Python 3.11+, stdlib only.

## License

See `LICENSE.md`.

## Connect with me

[LinkedIn](https://www.linkedin.com/in/francescopl/) · [Kaggle](https://www.kaggle.com/francescopaolol)

