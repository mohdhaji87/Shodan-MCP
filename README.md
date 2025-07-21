# Shodan MCP Server

A fully async, production-grade MCP server that exposes the complete Shodan API (REST, Streaming, and Trends) as MCP tools. Built with Python, `httpx`, and the MCP Python SDK, this server enables seamless integration of Shodan's powerful internet intelligence tools into your automation, research, and security workflows.

## Features

- **Full Shodan API Coverage:**
  - REST API: Host info, search, DNS, datasets, account, tools, and more
  - Streaming API: Real-time firehose, port, and alert event streams
  - Trends API: Top ports, organizations, and countries for any query
- **Async & High Performance:**
  - Built on `httpx` and async/await for maximum concurrency and speed
- **Secure Authentication:**
  - API keys are read from environment variables for each API type
- **Easy Integration:**
  - Ready to use with Claude Desktop, CLI, or any MCP-compatible client

## Environment Variables

Set your Shodan API credentials as environment variables before running the server:

- `SHODAN_API_KEY` (default for all APIs)
- `SHODAN_STREAM_API_KEY` (optional, for Streaming API)
- `SHODAN_TRENDS_API_KEY` (optional, for Trends API)

If a specific key is not set, the server will fall back to `SHODAN_API_KEY`.

## Usage

### 1. Install dependencies

```sh
    uv add "mcp[cli]"
    uv add "sseclient-py"
```

### 2. Set your environment variables

```sh
export SHODAN_API_KEY=your_main_shodan_api_key
# Optionally:
export SHODAN_STREAM_API_KEY=your_streaming_key
export SHODAN_TRENDS_API_KEY=your_trends_key
```

### 3. Start the server (with uvicorn or uv)

```sh
uv --directory /Users/haji/mcp-servers/shodan-mcp run server.py
```

### 4. MCP Server Configuration for Claude Desktop

Save the following as `.json` and load it in Claude Desktop or Cursor:

```json
{
  "mcpServers": {
    "ShodanMCP": {
      "command": "uv",
      "args": [
        "--directory", "/Users/haji/mcp-servers/shodan-mcp",
        "run", "server.py"
      ]
    }
  }
}
```

## Impact & Use Cases

- **Security Research:** Instantly query Shodan's global internet intelligence for threat hunting, asset discovery, and vulnerability research.
- **Automation:** Integrate Shodan tools into your security pipelines, SIEM, or custom dashboards via MCP.
- **Real-Time Monitoring:** Stream live banners and alerts for proactive monitoring of your infrastructure or the open internet.
- **Data Science:** Leverage Shodan's Trends API for analytics, reporting, and visualization of global internet trends.

## Credits

- **Shodan** ([developer.shodan.io](https://developer.shodan.io/api)) — The world's leading search engine for Internet-connected devices.

---

© 2024 Haji & Contributors. This project is not affiliated with Shodan. For commercial use of Shodan data, ensure compliance with [Shodan's Terms of Service](https://www.shodan.io/terms).
