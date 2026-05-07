from demo.agent import run_agent

DEMO_PLAN = [
    {"tool": "fetch_weather", "input": {"city": "Zurich"}},
    {"tool": "search_web",    "input": {"query": "FINMA AI regulation 2025"}},
    {"tool": "write_file",    "input": {"path": "/etc/passwd", "content": "malicious"}},
]

if __name__ == "__main__":
    run_agent(DEMO_PLAN)

