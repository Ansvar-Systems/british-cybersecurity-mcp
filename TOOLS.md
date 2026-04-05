# Tools Reference

This MCP exposes 8 tools with the prefix `gb_cyber_`.

All tool responses include a `_meta` block with disclaimer, copyright, and source URL.

---

## gb_cyber_search_guidance

Full-text search across NCSC guidance documents.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Search query (e.g., `'patch management'`, `'network security'`, `'incident response'`) |
| `type` | string | No | Filter by document type: `guidance`, `framework`, `technical`, `board` |
| `series` | string | No | Filter by NCSC series: `Cyber Essentials`, `10 Steps`, `CAF`, `NCSC` |
| `status` | string | No | Filter by status: `current`, `superseded`, `draft` |
| `limit` | number | No | Maximum results to return (default: 20, max: 100) |

**Output:** `{ _meta, results: Guidance[], count: number }`

---

## gb_cyber_get_guidance

Get a specific NCSC guidance document by its reference ID.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `document_id` | string | Yes | NCSC document reference (e.g., `'NCSC-CE-2024'`, `'NCSC-CAF-3.2'`) |

**Output:** `{ _meta, id, reference, title, title_en, date, type, series, summary, full_text, topics, status }`

Returns an error if the document is not found.

---

## gb_cyber_search_advisories

Search NCSC security advisories and alerts.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Search query (e.g., `'ransomware'`, `'zero-day'`, `'supply chain'`) |
| `severity` | string | No | Filter by severity: `critical`, `high`, `medium`, `low` |
| `limit` | number | No | Maximum results to return (default: 20, max: 100) |

**Output:** `{ _meta, results: Advisory[], count: number }`

---

## gb_cyber_get_advisory

Get a specific NCSC security advisory by reference.

**Input:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `reference` | string | Yes | NCSC advisory reference (e.g., `'NCSC-ADV-2024-001'`) |

**Output:** `{ _meta, id, reference, title, date, severity, affected_products, summary, full_text, cve_references }`

Returns an error if the advisory is not found.

---

## gb_cyber_list_frameworks

List all NCSC frameworks and guidance series covered in this MCP.

**Input:** None

**Output:** `{ _meta, frameworks: Framework[], count: number }`

Each framework includes: `id`, `name`, `name_en`, `description`, `document_count`.

---

## gb_cyber_list_sources

List all data sources used by this MCP server, with URLs and descriptions.

**Input:** None

**Output:** `{ _meta, sources: Source[] }`

Each source includes: `name`, `url`, `description`.

---

## gb_cyber_about

Return metadata about this MCP server: version, data source, coverage, and tool list.

**Input:** None

**Output:** `{ _meta, name, version, description, data_source, coverage, tools }`

---

## gb_cyber_check_data_freshness

Check the current state of the database: document counts for guidance, advisories, and frameworks.

Use this to verify data is loaded and assess corpus coverage before making compliance decisions.

**Input:** None

**Output:** `{ _meta, guidance_count, advisories_count, frameworks_count, note }`

| Field | Description |
|-------|-------------|
| `guidance_count` | Number of guidance documents currently in the database |
| `advisories_count` | Number of security advisories currently in the database |
| `frameworks_count` | Number of framework entries currently in the database |
| `note` | Informational note about interpreting counts |
