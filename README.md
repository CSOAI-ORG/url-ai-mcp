# Url Ai

> By [MEOK AI Labs](https://meok.ai) — MEOK AI Labs MCP Server

URL AI MCP Server — URL parsing and analysis tools.

## Installation

```bash
pip install url-ai-mcp
```

## Usage

```bash
# Run standalone
python server.py

# Or via MCP
mcp install url-ai-mcp
```

## Tools

### `parse_url`
Parse a URL into its components with detailed analysis.

**Parameters:**
- `url` (str)

### `shorten_url_data`
Generate a deterministic short URL hash (does not create actual redirect).

**Parameters:**
- `url` (str)

### `check_url_safety`
Analyze URL for potential safety issues (heuristic-based, no external calls).

**Parameters:**
- `url` (str)

### `extract_metadata`
Extract metadata from URL structure (no HTTP requests).

**Parameters:**
- `url` (str)


## Authentication

Free tier: 15 calls/day. Upgrade at [meok.ai/pricing](https://meok.ai/pricing) for unlimited access.

## Links

- **Website**: [meok.ai](https://meok.ai)
- **GitHub**: [CSOAI-ORG/url-ai-mcp](https://github.com/CSOAI-ORG/url-ai-mcp)
- **PyPI**: [pypi.org/project/url-ai-mcp](https://pypi.org/project/url-ai-mcp/)

## License

MIT — MEOK AI Labs
