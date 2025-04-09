from mcp import server
from mcp.server.fastmcp import FastMCP
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from dotenv import load_dotenv
import os
import sys
from typing import Any

# === Load environment variables ===
load_dotenv()

# === Define logging placeholders ===
def log_debug(message: str):
    """Log debug messages to stderr to avoid MCP protocol conflicts."""
    print(f"DEBUG: {message}", file=sys.stderr)

def log_memory_usage():
    """Log memory usage to stderr."""
    print("DEBUG: Memory usage check placeholder.", file=sys.stderr)

# === Config ===
OTX_API_KEY = os.getenv("OTX_API_KEY")
otx = OTXv2(OTX_API_KEY)

mcp = FastMCP("otx")

@mcp.tool()
async def search_indicators(keyword: str) -> Any:
    """Search OTX for pulses by keyword."""
    return otx.search_pulses(keyword)

@mcp.tool()
async def get_pulse(pulse_id: str) -> Any:
    """Get full details of a Pulse using its ID, minus indicators."""
    try:
        log_debug(f"Calling get_pulse with pulse_id={pulse_id}")
        pulse = otx.get_pulse_details(pulse_id)
        pulse.pop("indicators", None)  # Remove bulky field
        log_memory_usage()
        return pulse
    except Exception as e:
        log_debug(f"Error in get_pulse: {e}")
        return {"error": str(e)}

@mcp.tool()
async def extract_indicators_from_pulse(pulse_id: str) -> Any:
    """Extract a list of indicators from a given Pulse ID."""
    try:
        pulse = otx.get_pulse_details(pulse_id)
        indicators = pulse.get("indicators", [])
        # Limit number of indicators to avoid memory overload
        MAX_INDICATORS = 10
        return [
            {
                "indicator": i.get("indicator"),
                "type": i.get("type"),
                "description": i.get("description", "")
            }
            for i in indicators[:MAX_INDICATORS]
        ]
    except Exception as e:
        return {"error": str(e)}

mcp.list_resources = lambda: []
mcp.list_prompts = lambda: []

if __name__ == "__main__":
    mcp.run(transport="stdio")
