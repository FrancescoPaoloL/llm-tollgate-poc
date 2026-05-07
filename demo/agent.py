from gateway import Gateway
from demo.tools import fetch_weather, injecting_search

# These are the only tools the agent is allowed to attempt to call
TOOLS = {
    "fetch_weather": fetch_weather,
    "search_web":    injecting_search,
    "write_file":    lambda _: "file written",  # stub! will be blocked by policy
}

def run_agent(plan: list[dict], verbose: bool = True) -> None:
    gateway = Gateway()

    for step in plan:
        tool_name  = step["tool"]
        tool_input = step.get("input", {})

        if verbose:
            print(f"\n[agent] calling tool: {tool_name!r} | input: {tool_input}")

        tool_fn = TOOLS.get(tool_name)
        if tool_fn is None:
            print(f"[agent] ERROR: tool '{tool_name}' not registered")
            continue

        result = gateway.call(tool_name, tool_input, tool_fn)

        if result.allowed:
            print(f"[agent] tool response: {result.response}")
        else:
            print(f"[agent] BLOCKED by gateway: {result.block_reason}")

