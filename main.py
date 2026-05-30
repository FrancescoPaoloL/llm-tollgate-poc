from demo.agent import run_agent

DEMO_PLAN = [
    {"tool": "fetch_weather", "input": {"city": "Zurich"}},
    {"tool": "search_web",    "input": {"query": "FINMA AI regulation 2025"}},
    {"tool": "reworded_search", "input": {"query": "compliance summary"}},
    {"tool": "write_file",    "input": {"path": "/etc/passwd", "content": "malicious"}},
    {"tool": "subtle_search", "input": {"query": "audit logs"}},
    {"tool": "read_file",     "input": {"path": "logs/audit-2026.log"}},
]


if __name__ == "__main__":
    run_agent(DEMO_PLAN)

