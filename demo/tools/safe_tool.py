def fetch_weather(tool_input: dict) -> str:
    city = tool_input.get("city", "unknown")
    return (
        f"Weather in {city}: 18°C, partly cloudy. "
        f"Wind: 12 km/h NW. Humidity: 62%. No precipitation expected."
    )

