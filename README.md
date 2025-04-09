# OTX MCP Server

A Model Context Protocol (MCP) server for AlienVault OTX (Open Threat Exchange) that provides a comprehensive interface to the OTX API.

## Overview

This MCP server allows you to interact with the AlienVault OTX platform through the Model Context Protocol. The Model Context Protocol (MCP) is an innovative standard that enables applications to provide context and functionality to Large Language Models (LLMs) in a secure, standardized way. Think of it like a web API specifically designed for LLM interactions.

MCP servers can:
- Expose data through **Resources** (used to load information into the LLM's context)
- Provide functionality through **Tools** (used to execute code or produce side effects)
- Define interaction patterns through **Prompts** (reusable templates for LLM interactions)

This server implements the Tools functionality of MCP, providing a comprehensive set of tools for interacting with the OTX platform. It allows AI systems like Claude to retrieve and analyze threat indicators and Pulses in real-time.

## Features

- **Indicator Search and Analysis**: Search for indicators, get detailed information about specific indicators, and validate indicators
- **Pulse Management**: Create, edit, and manage threat intelligence pulses
- **User Interaction**: Follow users, subscribe to pulses, and manage your OTX network
- **URL Analysis**: Submit URLs for analysis to identify potential threats
- **Event Monitoring**: Track recent events and activities on OTX

## Installation

### Option 1: Using Docker (Recommended)

1. Export your OTX API key as an environment variable:
   ```
   export OTX_API_KEY=your_api_key_here
   ```

2. Pull the Docker image from GitHub Container Registry:
   ```
   docker pull ghcr.io/mrwadams/otx-mcp:latest
   ```

3. Run the container with your OTX API key:
   ```
   docker run --rm -i -e OTX_API_KEY=$OTX_API_KEY ghcr.io/mrwadams/otx-mcp:latest
   ```

### Option 2: Local Installation

1. Clone this repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Export your OTX API key as an environment variable:
   ```
   export OTX_API_KEY=your_api_key_here
   ```
   Or create a `.env` file with:
   ```
   OTX_API_KEY=your_api_key_here
   ```

## Usage

### Running the MCP Server

#### With Docker:
```
docker run --rm -i -e OTX_API_KEY=$OTX_API_KEY ghcr.io/mrwadams/otx-mcp:latest
```

#### Locally:
```
python main.py
```

The server will listen for MCP protocol messages on stdin/stdout.

### Using with Claude Desktop

To use this MCP server with Claude Desktop, add the following to your Claude Desktop config file (`claude_desktop_config.json`):

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
      "ghcr.io/mrwadams/otx-mcp:latest"
    ]
  }
}
```

Make sure you have exported your OTX API key as an environment variable before starting Claude Desktop.

## Available Tools

The MCP server provides the following tools:

### Indicator Tools
- `search_indicators`: Search OTX for pulses containing indicators matching a keyword
- `get_indicator_details`: Get detailed information about a specific indicator
- `get_indicator_details_full`: Get all available details about a specific indicator
- `validate_indicator`: Validate an indicator before adding it to a pulse

### Pulse Tools
- `get_pulse`: Get full details of a Pulse using its ID
- `extract_indicators_from_pulse`: Extract a list of indicators from a given Pulse ID
- `create_pulse`: Create a new pulse with threat intelligence information
- `get_my_pulses`: Get pulses created by the authenticated user
- `get_subscribed_pulses`: Get pulses the user is subscribed to

### User Tools
- `search_users`: Search for users in OTX
- `get_user`: Get information about a specific user
- `get_user_pulses`: Get pulses created by a specific user
- `follow_user`: Follow a user to receive notifications about their activities
- `unfollow_user`: Unfollow a user to stop receiving notifications

### Subscription Tools
- `subscribe_to_pulse`: Subscribe to a pulse to receive updates
- `unsubscribe_from_pulse`: Unsubscribe from a pulse to stop receiving updates

### Analysis Tools
- `submit_url`: Submit a URL for analysis
- `submit_urls`: Submit multiple URLs for analysis
- `get_recent_events`: Get recent events/activities from OTX

## Example Queries

Here are some example queries you can run using the MCP server with an LLM like Claude:

### Searching for Threat Intelligence

```
Can you search OTX for any information about recent ransomware attacks?
```

```
I need to find threat intelligence about CVE-2023-1234. Can you search OTX for me?
```

### Getting Indicator Details

```
OTX: Check indicators for google.com
```

```
Is 8.8.8.8 a malicious IP address? Can you check its reputation in OTX?
```

```
I found a suspicious domain called example.com. Can you get all the information about it from OTX?
```

### Working with Pulses

```
I have a pulse ID 5f7c8e9a1b2c3d4e5f6a7b8c9d0e1f2. Can you get the details for me?
```

```
Can you extract all the indicators from pulse 5f7c8e9a1b2c3d4e5f6a7b8c9d0e1f2?
```

### Creating a New Pulse

```
I need to create a new pulse about a ransomware campaign targeting healthcare organizations. The indicators include malicious-domain.com, 192.168.1.1, and https://malicious-domain.com/payload.exe. Can you help me create this pulse?
```

### User Interaction

```
Can you search for users with "AlienVault" in their name or username?
```

```
I want to follow the AlienVault user to get notifications about their activities.
```

```
Can you subscribe me to pulse 5f7c8e9a1b2c3d4e5f6a7b8c9d0e1f2?
```

### URL Analysis

```
I found a suspicious website at https://suspicious-website.com. Can you submit it for analysis?
```

### Monitoring Events

```
What are the 10 most recent events from OTX?
```

These natural language queries demonstrate how an LLM can understand your intent and use the appropriate MCP tools to fulfill your request, making it much easier to interact with the OTX platform without needing to know the specific API calls or parameters.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [AlienVault OTX](https://otx.alienvault.com/)
- [Model Context Protocol](https://modelcontextprotocol.io)