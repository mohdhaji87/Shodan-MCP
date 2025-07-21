import os
import httpx
import asyncio
from typing import Optional
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Shodan MCP Server")

SHODAN_API_BASE = "https://api.shodan.io"
SHODAN_STREAM_BASE = "https://stream.shodan.io"
SHODAN_TRENDS_BASE = "https://trends.shodan.io"

# Helper to get API key
def get_api_key(api_key: Optional[str] = None, api_type: Optional[str] = None) -> str:
    """
    Get the API key for the given API type (rest, stream, trends).
    Priority: explicit argument > env var for type > SHODAN_API_KEY
    """
    if api_key:
        return api_key
    if api_type == "stream":
        key = os.getenv("SHODAN_STREAM_API_KEY")
        if key:
            return key
    if api_type == "trends":
        key = os.getenv("SHODAN_TRENDS_API_KEY")
        if key:
            return key
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        raise ValueError("Shodan API key must be provided as argument or in SHODAN_API_KEY env var.")
    return key

# --- REST API TOOLS (async, httpx) ---

@mcp.tool()
async def shodan_host_info(ip: str, api_key: Optional[str] = None, history: Optional[bool] = False, minify: Optional[bool] = False) -> dict:
    """Returns all services that have been found on the given host IP."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    if history:
        params["history"] = "true"
    if minify:
        params["minify"] = "true"
    url = f"{SHODAN_API_BASE}/shodan/host/{ip}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_host_count(query: str, api_key: Optional[str] = None, facets: Optional[str] = None) -> dict:
    """Search Shodan without results, only returns the total number of results and facet info."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key, "query": query}
    if facets:
        params["facets"] = facets
    url = f"{SHODAN_API_BASE}/shodan/host/count"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_dns_resolve(hostnames: str, api_key: Optional[str] = None) -> dict:
    """Look up the IP address for the provided list of hostnames (comma-separated)."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key, "hostnames": hostnames}
    url = f"{SHODAN_API_BASE}/dns/resolve"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_api_info(api_key: Optional[str] = None) -> dict:
    """Returns information about the API plan belonging to the given API key."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/api-info"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_host_search(query: str, api_key: Optional[str] = None, facets: Optional[str] = None, page: Optional[int] = 1, minify: Optional[bool] = False) -> dict:
    """Search Shodan using the same query syntax as the website and return up to 100 results per page."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key, "query": query, "page": page}
    if facets:
        params["facets"] = facets
    if minify:
        params["minify"] = "true"
    url = f"{SHODAN_API_BASE}/shodan/host/search"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_host_search_facets(api_key: Optional[str] = None) -> dict:
    """List all search facets that can be used when searching Shodan."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/shodan/host/search/facets"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_ports(api_key: Optional[str] = None) -> dict:
    """List all ports that Shodan is crawling on the Internet."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/shodan/ports"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_protocols(api_key: Optional[str] = None) -> dict:
    """List all protocols that can be used when performing on-demand Internet scans via Shodan."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/shodan/protocols"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_query(api_key: Optional[str] = None, page: Optional[int] = 1) -> dict:
    """List the saved search queries in Shodan."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key, "page": page}
    url = f"{SHODAN_API_BASE}/shodan/query"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_query_search(query: str, api_key: Optional[str] = None, page: Optional[int] = 1) -> dict:
    """Search the directory of search queries that users have saved in Shodan."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key, "query": query, "page": page}
    url = f"{SHODAN_API_BASE}/shodan/query/search"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_query_tags(api_key: Optional[str] = None, size: Optional[int] = 10) -> dict:
    """List the most popular tags for the saved search queries in Shodan."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key, "size": size}
    url = f"{SHODAN_API_BASE}/shodan/query/tags"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_dns_reverse(ips: str, api_key: Optional[str] = None) -> dict:
    """Look up the hostnames that have been defined for the given list of IP addresses (comma-separated)."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key, "ips": ips}
    url = f"{SHODAN_API_BASE}/dns/reverse"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_tools_httpheaders(api_key: Optional[str] = None) -> dict:
    """Shows the HTTP headers that your client sends when connecting to a webserver."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/tools/httpheaders"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_tools_myip(api_key: Optional[str] = None) -> str:
    """Get your current IP address as seen from the Internet."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/tools/myip"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.text

@mcp.tool()
async def shodan_data(api_key: Optional[str] = None) -> dict:
    """List all datasets that are available for download."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/shodan/data"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_data_dataset(dataset: str, api_key: Optional[str] = None) -> dict:
    """Get information about a specific dataset available for download."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/shodan/data/{dataset}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_data_dataset_search(dataset: str, query: str, api_key: Optional[str] = None, page: Optional[int] = 1) -> dict:
    """Search within a dataset available for download."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key, "query": query, "page": page}
    url = f"{SHODAN_API_BASE}/shodan/data/{dataset}/search"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_account_profile(api_key: Optional[str] = None) -> dict:
    """Get information about the Shodan account linked to the API key."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/account/profile"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_tools_ping(host: str, api_key: Optional[str] = None) -> dict:
    """Ping a host to see if it is reachable from Shodan's servers."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key, "host": host}
    url = f"{SHODAN_API_BASE}/tools/ping"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_tools_ports(api_key: Optional[str] = None) -> dict:
    """List all ports that Shodan is crawling on the Internet (utility endpoint)."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/tools/ports"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_tools_protocols(api_key: Optional[str] = None) -> dict:
    """List all protocols that can be used when performing on-demand Internet scans via Shodan (utility endpoint)."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/tools/protocols"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_tools_uptime(api_key: Optional[str] = None) -> dict:
    """Get the uptime of Shodan's servers."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key}
    url = f"{SHODAN_API_BASE}/tools/uptime"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_tools_whois(domain: str, api_key: Optional[str] = None) -> dict:
    """Get WHOIS information for a domain."""
    key = get_api_key(api_key, api_type="rest")
    params = {"key": key, "domain": domain}
    url = f"{SHODAN_API_BASE}/tools/whois"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

# --- Streaming API (async, httpx, manual SSE parsing) ---

async def _parse_sse_events(aiter, limit: int = 10):
    events = []
    buffer = ""
    async for chunk in aiter:
        buffer += chunk.decode()
        while "\n\n" in buffer:
            event, buffer = buffer.split("\n\n", 1)
            if event.strip():
                data_lines = [line[6:] for line in event.splitlines() if line.startswith("data: ")]
                if data_lines:
                    events.append("\n".join(data_lines))
            if limit and len(events) >= limit:
                return events
    return events

@mcp.tool()
async def shodan_stream_firehose(api_key: Optional[str] = None, limit: Optional[int] = 10) -> list:
    """Stream the global firehose of all data Shodan collects in real time. Returns up to 'limit' events."""
    key = get_api_key(api_key, api_type="stream")
    url = f"{SHODAN_STREAM_BASE}/shodan/banners?key={key}"
    limit_val = limit if limit is not None else 10
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            return await _parse_sse_events(resp.aiter_bytes(), limit_val)

@mcp.tool()
async def shodan_stream_ports(port: int, api_key: Optional[str] = None, limit: Optional[int] = 10) -> list:
    """Stream banners for a specific port in real time. Returns up to 'limit' events."""
    key = get_api_key(api_key, api_type="stream")
    url = f"{SHODAN_STREAM_BASE}/shodan/port/{port}?key={key}"
    limit_val = limit if limit is not None else 10
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            return await _parse_sse_events(resp.aiter_bytes(), limit_val)

@mcp.tool()
async def shodan_stream_alert(api_key: Optional[str] = None, limit: Optional[int] = 10) -> list:
    """Stream banners for the networks monitored by your Shodan account. Returns up to 'limit' events."""
    key = get_api_key(api_key, api_type="stream")
    url = f"{SHODAN_STREAM_BASE}/shodan/alert?key={key}"
    limit_val = limit if limit is not None else 10
    async with httpx.AsyncClient(timeout=None) as client:
        async with client.stream("GET", url) as resp:
            resp.raise_for_status()
            return await _parse_sse_events(resp.aiter_bytes(), limit_val)

# --- Trends API (async, httpx) ---

@mcp.tool()
async def shodan_trends_top_ports(query: str, days: int = 30, api_key: Optional[str] = None) -> dict:
    """Get the top ports for a search query over a period of days."""
    key = get_api_key(api_key, api_type="trends")
    url = f"{SHODAN_TRENDS_BASE}/api/v1/top-ports"
    params = {"key": key, "query": query, "days": days}
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_trends_top_orgs(query: str, days: int = 30, api_key: Optional[str] = None) -> dict:
    """Get the top organizations for a search query over a period of days."""
    key = get_api_key(api_key, api_type="trends")
    url = f"{SHODAN_TRENDS_BASE}/api/v1/top-orgs"
    params = {"key": key, "query": query, "days": days}
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

@mcp.tool()
async def shodan_trends_top_countries(query: str, days: int = 30, api_key: Optional[str] = None) -> dict:
    """Get the top countries for a search query over a period of days."""
    key = get_api_key(api_key, api_type="trends")
    url = f"{SHODAN_TRENDS_BASE}/api/v1/top-countries"
    params = {"key": key, "query": query, "days": days}
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

if __name__ == "__main__":
    mcp.run()
