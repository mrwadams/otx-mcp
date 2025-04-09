# OTX MCP Server

This project provides an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that exposes tools for interacting with [AlienVault OTX](https://otx.alienvault.com/) threat intelligence data. It allows AI systems like Claude to retrieve and analyse threat indicators and Pulses in real-time.

## 🚀 Features

- **search_indicators**: Look up threat indicators (IPs, domains, hashes) using a keyword and type.
- **get_pulse**: Retrieve metadata about a specific OTX Pulse by its ID (indicators are excluded for performance).
- **extract_indicators_from_pulse**: Get a structured list of indicators from a Pulse ID, capped for performance.

## 🐳 Running with Docker

This repo includes a Dockerfile to simplify usage and deployment.

### Build the image

```bash
docker build -t otx-mcp .
```

### Run the container

Set your API key before running:

```bash
export OTX_API_KEY=your_actual_otx_api_key
docker run --rm -i -e OTX_API_KEY=$OTX_API_KEY otx-mcp
```

## 🧠 Usage with Claude (MCP Client)

Add the following to your Claude Desktop config file (`claude_desktop_config.json`):

```json
"mcpServers": {
  "otx": {
    "command": "docker",
    "args": [
      "run",
      "-i",
      "--rm",
      "-e",
      "OTX_API_KEY",
      "otx-mcp:latest"
    ]
  }
}

## 🐞 Debug Logging

This MCP server logs detailed debug and memory usage information to `stderr`. These logs are captured by Docker and helpful for diagnosing errors and performance issues. All logs are isolated from the MCP protocol output to ensure stability.
```