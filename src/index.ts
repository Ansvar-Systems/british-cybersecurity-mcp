#!/usr/bin/env node

/**
 * British Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying NCSC (UK National Cyber Security Centre)
 * guidance documents, Cyber Essentials, CAF, 10 Steps to Cyber Security,
 * and security advisories.
 *
 * Tool prefix: gb_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
} from "./db.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "british-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "gb_cyber_search_guidance",
    description:
      "Full-text search across NCSC guidance documents. Covers Cyber Essentials, 10 Steps to Cyber Security, Cyber Assessment Framework (CAF), board-level guidance, and technical publications. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'patch management', 'network security', 'incident response')",
        },
        type: {
          type: "string",
          enum: ["guidance", "framework", "technical", "board"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["Cyber Essentials", "10 Steps", "CAF", "NCSC"],
          description: "Filter by NCSC series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "gb_cyber_get_guidance",
    description:
      "Get a specific NCSC guidance document by reference (e.g., 'NCSC-CE-2024', 'NCSC-10STEPS-2023', 'NCSC-CAF-3.2').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "NCSC document reference (e.g., 'NCSC-CE-2024', 'NCSC-CAF-3.2')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "gb_cyber_search_advisories",
    description:
      "Search NCSC security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'ransomware', 'zero-day', 'supply chain')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "gb_cyber_get_advisory",
    description:
      "Get a specific NCSC security advisory by reference (e.g., 'NCSC-ADV-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "NCSC advisory reference (e.g., 'NCSC-ADV-2024-001')",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "gb_cyber_list_frameworks",
    description:
      "List all NCSC frameworks and guidance series covered in this MCP, including Cyber Essentials, 10 Steps to Cyber Security, and the Cyber Assessment Framework (CAF).",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "gb_cyber_list_sources",
    description: "List all data sources used by this MCP server, with URLs and descriptions.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "gb_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["guidance", "framework", "technical", "board"]).optional(),
  series: z.enum(["Cyber Essentials", "10 Steps", "CAF", "NCSC"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- Helper ------------------------------------------------------------------

function textContent(data: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(data, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "gb_cyber_search_guidance": {
        const parsed = SearchGuidanceArgs.parse(args);
        const results = searchGuidance({
          query: parsed.query,
          type: parsed.type,
          series: parsed.series,
          status: parsed.status,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "gb_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
        }
        return textContent(doc);
      }

      case "gb_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        return textContent({ results, count: results.length });
      }

      case "gb_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
        }
        return textContent(advisory);
      }

      case "gb_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
      }

      case "gb_cyber_list_sources": {
        return textContent({
          sources: [
            {
              name: "NCSC (National Cyber Security Centre)",
              url: "https://www.ncsc.gov.uk/",
              description: "Security guidance, CAF, threat reports",
            },
            {
              name: "Cyber Assessment Framework (CAF)",
              url: "https://www.ncsc.gov.uk/collection/caf",
              description: "14 principles, 39 contributing outcomes",
            },
            {
              name: "NCSC Security Advisories",
              url: "https://www.ncsc.gov.uk/section/keep-up-to-date/threat-reports",
              description: "CVE-tagged advisories, severity ratings",
            },
            {
              name: "10 Steps to Cyber Security",
              url: "https://www.ncsc.gov.uk/collection/10-steps",
              description: "Foundational security framework",
            },
            {
              name: "Cyber Essentials",
              url: "https://www.ncsc.gov.uk/cyberessentials",
              description: "Certification scheme requirements",
            },
            {
              name: "NIS Regulations 2018",
              url: "https://www.legislation.gov.uk/",
              description: "Network and information systems security",
            },
          ],
        });
      }

      case "gb_cyber_about": {
        return textContent({
          name: SERVER_NAME,
          version: pkgVersion,
          description:
            "NCSC (UK National Cyber Security Centre) MCP server. Provides access to NCSC guidance including Cyber Essentials, 10 Steps to Cyber Security, Cyber Assessment Framework (CAF), and security advisories.",
          data_source: "NCSC (https://www.ncsc.gov.uk/)",
          coverage: {
            guidance: "Cyber Essentials, 10 Steps to Cyber Security, Cyber Assessment Framework (CAF), board-level guidance",
            advisories: "NCSC security advisories and alerts",
            frameworks: "Cyber Essentials, 10 Steps, CAF",
          },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
        });
      }

      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorContent(`Error executing ${name}: ${message}`);
  }
});

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
