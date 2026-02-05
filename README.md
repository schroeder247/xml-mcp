# xml-mcp

An MCP server for XML processing — XPath queries, XSLT transforms, SOAP/WSDL tools, schema inference, and more.

Built in Rust as a single binary with zero runtime dependencies (except `xsltproc` for XSLT).

## Features

- **XPath 1.0** — query, set, add, delete nodes with full axis/predicate/function support
- **Streaming** — `count()` and attribute queries use streaming (fast on large files)
- **SOAP/WSDL** — parse envelopes, build requests, inspect WSDL services with sample generation
- **Schema** — infer structure from samples, generate mock XML, validate well-formedness
- **Conversion** — XML to/from JSON, pretty/compact/sorted formatting, diff two documents
- **XSLT 1.0** — transform via xsltproc

## Tools (20)

| Category | Tools |
|----------|-------|
| **Query** | `xpath_query`, `xml_tree`, `xml_validate` |
| **Modify** | `xpath_set`, `xpath_add`, `xpath_delete` |
| **Convert** | `xml_to_json`, `json_to_xml`, `xml_transform` |
| **Compare** | `xml_diff`, `xml_format` |
| **Schema** | `schema_infer`, `schema_store`, `schema_get`, `schema_list`, `schema_delete`, `xml_generate` |
| **SOAP/WSDL** | `soap_parse`, `soap_build`, `wsdl_inspect` |

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
# Binary at target/release/xml-mcp
```

## Configuration

Add to your MCP client config (e.g. Claude Desktop, Claude Code):

```json
{
  "mcpServers": {
    "xml-mcp": {
      "command": "xml-mcp"
    }
  }
}
```

## Quick Reference

```
XPath queries:    //elem, //elem/@attr, //elem[@id='x'], count(//elem)
XPath modify:     xpath_set, xpath_add (inside|before|after), xpath_delete
SOAP workflow:    wsdl_inspect → soap_build → [send] → soap_parse
Schema workflow:  schema_infer (store_as=name) → xml_generate
```

## Requirements

- Rust 2021 edition
- `xsltproc` (optional, for `xml_transform` only)

## License

MIT
