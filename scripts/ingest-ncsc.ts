/**
 * NCSC (UK National Cyber Security Centre) ingestion crawler.
 *
 * Discovers guidance documents and security advisories from ncsc.gov.uk via
 * the public sitemap, fetches each page, parses with cheerio, and writes to
 * the local SQLite DB used by british-cybersecurity-mcp.
 *
 * Source: https://www.ncsc.gov.uk/ — OGL-3.0 licensed Crown Copyright material.
 *
 *   - Guidance:  /guidance/<slug> and /report/<slug>  (structured publications)
 *   - Advisory:  /news/<slug>   filtered by advisory/alert/exploit/vulnerability
 *                /report/mar-*  (Malware Analysis Reports — advisory-shaped)
 *
 * robots.txt (checked 2026-05-28): User-agent: * Allow: / (Content-Signal
 * search=yes, ai-train=no). Ansvar use case = MCP search/lookup index. We
 * identify ourselves as AnsvarNCSCCrawler/1.0 and rate-limit ≥1s/request.
 *
 * Usage:
 *   npx tsx scripts/ingest-ncsc.ts                # full crawl, default caps
 *   npx tsx scripts/ingest-ncsc.ts --force        # drop & rebuild data/ncsc.db
 *   npx tsx scripts/ingest-ncsc.ts --dry-run      # fetch + parse, no DB writes
 *   npx tsx scripts/ingest-ncsc.ts --max-guidance=200
 *   npx tsx scripts/ingest-ncsc.ts --max-advisories=40
 *
 * Environment:
 *   NCSC_DB_PATH   path to SQLite DB (default: data/ncsc.db)
 *   NCSC_RATE_MS   delay between HTTP requests (default: 1200, min: 1000)
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["NCSC_DB_PATH"] ?? "data/ncsc.db";
const BASE_URL = "https://www.ncsc.gov.uk";
const SITEMAP_INDEX = `${BASE_URL}/sitemap.xml`;
const RATE_LIMIT_MS = Math.max(1000, Number(process.env["NCSC_RATE_MS"]) || 1200);
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 2500;
const REQUEST_TIMEOUT_MS = 30_000;
const USER_AGENT =
  "AnsvarNCSCCrawler/1.0 (+https://ansvar.eu; compliance research)";

const args = process.argv.slice(2);
const FORCE = args.includes("--force");
const DRY_RUN = args.includes("--dry-run");

function getNumberArg(flag: string, fallback: number): number {
  const found = args.find((a) => a.startsWith(`${flag}=`));
  if (!found) return fallback;
  const v = Number(found.slice(flag.length + 1));
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

const MAX_GUIDANCE = getNumberArg("--max-guidance", 150);
const MAX_ADVISORIES = getNumberArg("--max-advisories", 40);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string | null;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string;
  full_text: string;
  cve_references: string | null;
}

interface SitemapEntry {
  loc: string;
  lastmod?: string | undefined;
}

// ---------------------------------------------------------------------------
// Rate-limited fetch with retry
// ---------------------------------------------------------------------------

let lastRequestTime = 0;

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function rateLimitedFetch(url: string): Promise<Response> {
  const elapsed = Date.now() - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }

  let lastErr: Error | null = null;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      lastRequestTime = Date.now();
      const resp = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept:
            "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8",
        },
        redirect: "follow",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status} for ${url}`);
      }
      return resp;
    } catch (err) {
      lastErr = err instanceof Error ? err : new Error(String(err));
      console.warn(
        `  [retry ${attempt}/${MAX_RETRIES}] ${url}: ${lastErr.message}`,
      );
      if (attempt < MAX_RETRIES) {
        await sleep(RETRY_BACKOFF_MS * attempt);
      }
    }
  }
  throw lastErr ?? new Error(`fetch failed: ${url}`);
}

async function fetchText(url: string): Promise<string> {
  const resp = await rateLimitedFetch(url);
  return resp.text();
}

// ---------------------------------------------------------------------------
// Sitemap discovery
// ---------------------------------------------------------------------------

function parseSitemapXml(xml: string): SitemapEntry[] {
  const out: SitemapEntry[] = [];
  const re =
    /<(?:url|sitemap)>([\s\S]*?)<\/(?:url|sitemap)>/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    const body = m[1]!;
    const loc = /<loc>([^<]+)<\/loc>/.exec(body)?.[1]?.trim();
    if (!loc) continue;
    const lastmod = /<lastmod>([^<]+)<\/lastmod>/.exec(body)?.[1]?.trim();
    const entry: SitemapEntry = { loc };
    if (lastmod) entry.lastmod = lastmod;
    out.push(entry);
  }
  return out;
}

async function discoverSitemapUrls(): Promise<SitemapEntry[]> {
  console.log(`Fetching sitemap index ${SITEMAP_INDEX}`);
  const indexXml = await fetchText(SITEMAP_INDEX);
  const indexEntries = parseSitemapXml(indexXml);
  console.log(`  Found ${indexEntries.length} sub-sitemaps`);

  const all: SitemapEntry[] = [];
  for (const sm of indexEntries) {
    const xml = await fetchText(sm.loc);
    const entries = parseSitemapXml(xml);
    console.log(`  ${sm.loc} -> ${entries.length} URLs`);
    all.push(...entries);
  }
  return all;
}

// ---------------------------------------------------------------------------
// URL classification
// ---------------------------------------------------------------------------

const ADVISORY_KEYWORDS =
  /(alert|advisory|advisories|vulnerab|exploit|exploitation|ransom|malware|apt[-0-9]|cve|incident|attack|targeted|spyware|botnet|backdoor|mar-)/i;

function isGuidanceUrl(url: string): boolean {
  // Substantive publications: /guidance/<slug> or /report/<slug>
  return /^https:\/\/www\.ncsc\.gov\.uk\/(guidance|report)\/[^/]+$/.test(url);
}

function isAdvisoryUrl(url: string): boolean {
  if (!/^https:\/\/www\.ncsc\.gov\.uk\/news\/[^/]+$/.test(url)) {
    // Malware Analysis Reports under /report/mar-* are advisory-shaped
    if (/^https:\/\/www\.ncsc\.gov\.uk\/report\/mar-[^/]+$/.test(url)) {
      return true;
    }
    return false;
  }
  const slug = url.split("/").pop() ?? "";
  return ADVISORY_KEYWORDS.test(slug);
}

function slugFromUrl(url: string): string {
  const u = new URL(url);
  return u.pathname.replace(/^\/+|\/+$/g, "").replace(/\//g, "-");
}

// ---------------------------------------------------------------------------
// Page parsing
// ---------------------------------------------------------------------------

interface ParsedPage {
  title: string;
  description: string;
  date: string | null;
  bodyText: string;
}

function parsePage(html: string): ParsedPage | null {
  const $ = cheerio.load(html);
  const title = $("h1").first().text().trim();
  if (!title) return null;
  const description = ($("meta[name=description]").attr("content") ?? "").trim();
  const timeEl = $("time").first();
  const datetime = timeEl.attr("datetime") ?? "";
  const date = datetime ? datetime.slice(0, 10) : null;

  // Strip nav, header, footer, script, style from <main> before extracting text
  const main = $("main").first();
  if (!main.length) return null;
  main.find("script, style, nav, header, footer, form, aside, button").remove();
  main.find("[aria-hidden='true']").remove();
  const bodyText = main
    .text()
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();

  return { title, description, date, bodyText };
}

// ---------------------------------------------------------------------------
// Topic detection for guidance (lightweight, keyword-based)
// ---------------------------------------------------------------------------

const TOPIC_KEYWORDS: Record<string, RegExp> = {
  "cloud-security": /\bcloud\b/i,
  "zero-trust": /zero[- ]trust/i,
  cryptography: /\b(crypt|tls|certificate|pki|encryption)\b/i,
  "incident-management": /incident response|incident management/i,
  "supply-chain": /supply chain/i,
  "identity-access": /\b(identity|authentication|access control|mfa)\b/i,
  "network-security": /\b(network|firewall|vpn|dns)\b/i,
  ransomware: /ransom/i,
  "phishing-fraud": /\b(phishing|smishing|scam|fraud)\b/i,
  "device-security": /(byod|mobile device|endpoint|laptop)/i,
  "secure-design": /(secure (?:by )?design|architecture|principles)/i,
  governance: /(board|governance|risk management)/i,
  "data-protection": /\b(personal data|gdpr|data protection)\b/i,
  "operational-technology": /\b(ics|ot|scada|industrial control)\b/i,
  "ai-security": /\b(ai|machine learning|llm)\b/i,
};

function detectTopics(text: string): string[] {
  const out: string[] = [];
  for (const [topic, re] of Object.entries(TOPIC_KEYWORDS)) {
    if (re.test(text)) out.push(topic);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Series detection (lightweight) from URL slug / title
// ---------------------------------------------------------------------------

function detectGuidanceSeries(url: string, title: string): string | null {
  const slug = url.split("/").pop() ?? "";
  if (/10-steps/i.test(slug) || /10 steps/i.test(title)) return "10-steps";
  if (/cyber-essentials/i.test(slug) || /cyber essentials/i.test(title))
    return "cyber-essentials";
  if (/cloud-security-principle/i.test(slug)) return "cloud-security-principles";
  if (/(\bcaf\b|cyber assessment framework)/i.test(title)) return "caf";
  if (url.includes("/report/")) return "report";
  return null;
}

// ---------------------------------------------------------------------------
// CVE extraction
// ---------------------------------------------------------------------------

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/g;

function extractCves(text: string): string[] {
  const set = new Set<string>();
  for (const m of text.matchAll(CVE_RE)) set.add(m[0]);
  return [...set];
}

// ---------------------------------------------------------------------------
// Severity heuristic from advisory body
// ---------------------------------------------------------------------------

function detectSeverity(text: string): string | null {
  const low = text.toLowerCase();
  if (/\bcritical\b/.test(low)) return "critical";
  if (/\b(high (severity|impact)|severe)\b/.test(low)) return "high";
  if (/\bmedium (severity|impact)\b/.test(low)) return "medium";
  if (/\blow (severity|impact)\b/.test(low)) return "low";
  if (/(active(ly)? exploit|exploited in the wild|under exploitation)/.test(low))
    return "high";
  return null;
}

// ---------------------------------------------------------------------------
// Build guidance row
// ---------------------------------------------------------------------------

function buildGuidance(url: string, page: ParsedPage): GuidanceRow | null {
  if (page.bodyText.length < 400) return null; // skip stub pages
  const slug = url.split("/").pop() ?? "";
  const reference = `NCSC-${slug}`.slice(0, 200);
  const summary =
    page.description ||
    page.bodyText.split(/\n\n+/).find((p) => p.length > 60) ||
    page.bodyText.slice(0, 500);
  const topics = detectTopics(page.bodyText);
  const series = detectGuidanceSeries(url, page.title);
  const type = url.includes("/report/") ? "report" : "guidance";
  return {
    reference,
    title: page.title,
    title_en: page.title, // NCSC publishes in English
    date: page.date,
    type,
    series,
    summary: summary.slice(0, 2000),
    full_text: page.bodyText.slice(0, 50_000),
    topics: JSON.stringify(topics),
    status: "current",
  };
}

// ---------------------------------------------------------------------------
// Build advisory row
// ---------------------------------------------------------------------------

function buildAdvisory(url: string, page: ParsedPage): AdvisoryRow | null {
  if (page.bodyText.length < 300) return null;
  const slug = url.split("/").pop() ?? "";
  const reference = `NCSC-ADV-${slug}`.slice(0, 200);
  const cves = extractCves(page.bodyText);
  const severity = detectSeverity(page.bodyText);
  const summary =
    page.description ||
    page.bodyText.split(/\n\n+/).find((p) => p.length > 60) ||
    page.bodyText.slice(0, 500);
  return {
    reference,
    title: page.title,
    date: page.date,
    severity,
    affected_products: null,
    summary: summary.slice(0, 2000),
    full_text: page.bodyText.slice(0, 50_000),
    cve_references: cves.length > 0 ? JSON.stringify(cves) : null,
  };
}

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

function initDatabase(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });

  if (FORCE && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    console.log(`Deleted existing database at ${DB_PATH}`);
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);

  // Frameworks — NCSC publishes a stable set
  const insertFw = db.prepare(
    "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
  );
  for (const f of FRAMEWORKS) {
    insertFw.run(f.id, f.name, f.name_en, f.description, 0);
  }

  return db;
}

const FRAMEWORKS = [
  {
    id: "cyber-essentials",
    name: "Cyber Essentials",
    name_en: "Cyber Essentials",
    description:
      "UK government-backed scheme helping organisations protect against common cyber attacks. Defines five technical controls: firewalls, secure configuration, user access control, malware protection, and patch management.",
  },
  {
    id: "10-steps",
    name: "10 Steps to Cyber Security",
    name_en: "10 Steps to Cyber Security",
    description:
      "NCSC 10 Steps guidance for organisations on protecting themselves in cyberspace. Covers network security, user education, malware prevention, and incident management.",
  },
  {
    id: "caf",
    name: "Cyber Assessment Framework (CAF)",
    name_en: "Cyber Assessment Framework",
    description:
      "Systematic approach to assessing cyber risk management for operators of essential services under the NIS Regulations. Used by UK regulators and competent authorities.",
  },
  {
    id: "cloud-security-principles",
    name: "Cloud Security Principles",
    name_en: "Cloud Security Principles",
    description:
      "14 principles to consider when evaluating cloud services and to apply when migrating to cloud. Covers data protection in transit, asset protection, supply chain security, identity and authentication, and operational security.",
  },
];

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("NCSC ingestion crawler");
  console.log("======================");
  console.log(`DB:      ${DB_PATH}`);
  console.log(`Rate:    ${RATE_LIMIT_MS}ms/request`);
  console.log(`Caps:    guidance ${MAX_GUIDANCE}, advisories ${MAX_ADVISORIES}`);
  console.log(`Flags:   force=${FORCE} dry-run=${DRY_RUN}`);
  console.log();

  const db = initDatabase();

  const entries = await discoverSitemapUrls();
  console.log(`\nTotal sitemap URLs: ${entries.length}`);

  const guidanceUrls = entries
    .filter((e) => isGuidanceUrl(e.loc) && !isAdvisoryUrl(e.loc))
    .slice(0, MAX_GUIDANCE);
  const advisoryUrls = entries.filter((e) => isAdvisoryUrl(e.loc)).slice(0, MAX_ADVISORIES);

  console.log(`Guidance candidates:  ${guidanceUrls.length}`);
  console.log(`Advisory candidates:  ${advisoryUrls.length}\n`);

  const insertGuidance = db.prepare(
    `INSERT OR REPLACE INTO guidance
      (reference, title, title_en, date, type, series, summary, full_text, topics, status)
     VALUES (@reference, @title, @title_en, @date, @type, @series, @summary, @full_text, @topics, @status)`,
  );
  const insertAdvisory = db.prepare(
    `INSERT OR REPLACE INTO advisories
      (reference, title, date, severity, affected_products, summary, full_text, cve_references)
     VALUES (@reference, @title, @date, @severity, @affected_products, @summary, @full_text, @cve_references)`,
  );

  // Crawl guidance
  let guidanceInserted = 0;
  let guidanceSkipped = 0;
  console.log("--- Crawling guidance ---");
  for (let i = 0; i < guidanceUrls.length; i++) {
    const url = guidanceUrls[i]!.loc;
    try {
      const html = await fetchText(url);
      const page = parsePage(html);
      if (!page) {
        guidanceSkipped++;
        console.warn(`  [${i + 1}/${guidanceUrls.length}] parse-skip ${url}`);
        continue;
      }
      const row = buildGuidance(url, page);
      if (!row) {
        guidanceSkipped++;
        continue;
      }
      if (!DRY_RUN) insertGuidance.run(row);
      guidanceInserted++;
      if ((i + 1) % 10 === 0 || i === guidanceUrls.length - 1) {
        console.log(
          `  [${i + 1}/${guidanceUrls.length}] inserted=${guidanceInserted} skipped=${guidanceSkipped}`,
        );
      }
    } catch (err) {
      guidanceSkipped++;
      console.error(
        `  Error on ${url}: ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  // Crawl advisories
  let advisoryInserted = 0;
  let advisorySkipped = 0;
  console.log("\n--- Crawling advisories ---");
  for (let i = 0; i < advisoryUrls.length; i++) {
    const url = advisoryUrls[i]!.loc;
    try {
      const html = await fetchText(url);
      const page = parsePage(html);
      if (!page) {
        advisorySkipped++;
        continue;
      }
      const row = buildAdvisory(url, page);
      if (!row) {
        advisorySkipped++;
        continue;
      }
      if (!DRY_RUN) insertAdvisory.run(row);
      advisoryInserted++;
      if ((i + 1) % 5 === 0 || i === advisoryUrls.length - 1) {
        console.log(
          `  [${i + 1}/${advisoryUrls.length}] inserted=${advisoryInserted} skipped=${advisorySkipped}`,
        );
      }
    } catch (err) {
      advisorySkipped++;
      console.error(
        `  Error on ${url}: ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  // Final framework document_count refresh
  if (!DRY_RUN) {
    const updateFw = db.prepare(
      `UPDATE frameworks SET document_count = (
         SELECT COUNT(*) FROM guidance WHERE series = ?
       ) WHERE id = ?`,
    );
    for (const f of FRAMEWORKS) updateFw.run(f.id, f.id);
  }

  console.log();
  console.log("================================");
  console.log("Ingestion complete");
  console.log(`  Guidance:   inserted=${guidanceInserted}  skipped=${guidanceSkipped}`);
  console.log(`  Advisories: inserted=${advisoryInserted}  skipped=${advisorySkipped}`);
  if (!DRY_RUN) {
    const g = (db.prepare("SELECT COUNT(*) c FROM guidance").get() as { c: number }).c;
    const a = (db.prepare("SELECT COUNT(*) c FROM advisories").get() as { c: number }).c;
    const f = (db.prepare("SELECT COUNT(*) c FROM frameworks").get() as { c: number }).c;
    console.log(`  DB totals:  guidance=${g}  advisories=${a}  frameworks=${f}`);
  }
}

main().catch((err) => {
  console.error("FATAL:", err);
  process.exit(1);
});
