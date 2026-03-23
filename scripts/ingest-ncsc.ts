#!/usr/bin/env npx tsx
/**
 * NCSC (UK National Cyber Security Centre) ingestion crawler.
 *
 * Crawls ncsc.gov.uk for guidance documents, security advisories/alerts,
 * and framework collections. Parses HTML with cheerio and stores results
 * in the SQLite database used by the MCP server.
 *
 * Usage:
 *   npx tsx scripts/ingest-ncsc.ts                  # full crawl
 *   npx tsx scripts/ingest-ncsc.ts --dry-run         # fetch + parse, no DB writes
 *   npx tsx scripts/ingest-ncsc.ts --resume           # skip already-ingested references
 *   npx tsx scripts/ingest-ncsc.ts --force            # overwrite existing records
 *   npx tsx scripts/ingest-ncsc.ts --dry-run --resume # preview what would be added
 *
 * Environment:
 *   NCSC_DB_PATH  — path to SQLite database (default: data/ncsc.db)
 *   NCSC_RATE_MS  — delay between requests in ms (default: 1500)
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["NCSC_DB_PATH"] ?? "data/ncsc.db";
const RATE_MS = Number(process.env["NCSC_RATE_MS"]) || 1500;
const BASE = "https://www.ncsc.gov.uk";
const USER_AGENT =
  "AnsvarBot/1.0 (+https://ansvar.eu; cybersecurity research crawler)";

const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 3000;
const REQUEST_TIMEOUT_MS = 30_000;

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const DRY_RUN = args.includes("--dry-run");
const RESUME = args.includes("--resume");
const FORCE = args.includes("--force");

if (FORCE && RESUME) {
  console.error("Error: --force and --resume are mutually exclusive.");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Curated URL lists — known working paths on ncsc.gov.uk
// ---------------------------------------------------------------------------

/**
 * Guidance URLs — individual guidance pages with structured content.
 * These are the primary content pages we want to ingest.
 */
const GUIDANCE_SEED_SLUGS: string[] = [
  // Cyber Essentials
  "guidance/cyber-essentials-requirements-for-it-infrastructure",
  "guidance/cyber-essentials-plus-an-introduction",
  "guidance/cyber-essentials-overview",
  // 10 Steps
  "guidance/10-steps-to-cyber-security",
  "guidance/10-steps-risk-management",
  "guidance/10-steps-engagement-and-training",
  "guidance/10-steps-asset-management",
  "guidance/10-steps-architecture-and-configuration",
  "guidance/10-steps-vulnerability-management",
  "guidance/10-steps-identity-and-access-management",
  "guidance/10-steps-data-security",
  "guidance/10-steps-logging-and-monitoring",
  "guidance/10-steps-incident-management",
  "guidance/10-steps-supply-chain-security",
  // Cloud security
  "guidance/cloud-security-guidance-introduction",
  "guidance/cloud-security-principle-1-data-in-transit-protection",
  "guidance/cloud-security-principle-2-asset-protection-and-resilience",
  "guidance/cloud-security-principle-3-separation-between-consumers",
  "guidance/cloud-security-principle-4-governance-framework",
  "guidance/cloud-security-principle-5-operational-security",
  "guidance/cloud-security-principle-6-personnel-security",
  "guidance/cloud-security-principle-7-secure-development",
  "guidance/cloud-security-principle-8-supply-chain-security",
  "guidance/cloud-security-principle-9-secure-user-management",
  "guidance/cloud-security-principle-10-identity-and-authentication",
  "guidance/cloud-security-principle-11-external-interface-protection",
  "guidance/cloud-security-principle-12-secure-service-administration",
  "guidance/cloud-security-principle-13-audit-information-and-alerting",
  "guidance/cloud-security-principle-14-secure-use-of-the-service",
  // Board-level / governance
  "guidance/board-level-cyber-security-questions",
  "guidance/introduction-to-cyber-security-for-board-members",
  // Incident management
  "guidance/actions-to-take-when-the-cyber-threat-is-heightened",
  "guidance/mitigating-malware-and-ransomware-attacks",
  "guidance/phishing",
  // Authentication & passwords
  "guidance/setting-up-two-factor-authentication-2fa",
  "guidance/password-guidance-simplifying-your-approach",
  "guidance/password-administration-for-system-owners",
  // Secure development
  "guidance/secure-development-and-deployment",
  "guidance/code-signing",
  // Network security
  "guidance/network-security",
  "guidance/using-tls-to-protect-data",
  "guidance/email-security-and-anti-spoofing",
  // Supply chain
  "guidance/mapping-your-supply-chain",
  "guidance/gaining-confidence-in-supply-chain-security",
  "guidance/assessing-supply-chain-security",
  "guidance/principles-for-supply-chain-security",
  // Zero trust
  "guidance/zero-trust-architecture-design-principles",
  // Logging and monitoring
  "guidance/introduction-logging-security-purposes",
  "guidance/logging-made-easy",
  // Vulnerability management
  "guidance/vulnerability-management",
  "guidance/vulnerability-disclosure-toolkit",
  // Encryption
  "guidance/using-tls-to-protect-data",
  // Device security
  "guidance/device-security-guidance-introduction",
  "guidance/managing-mobile-device-security",
  // AI security
  "guidance/ai-and-cyber-security",
  // Risk management
  "guidance/risk-management-collection",
  "guidance/summary-risk-methods-and-frameworks",
  // Penetration testing
  "guidance/penetration-testing",
  // BYOD
  "guidance/bring-your-own-device",
  // Secure by design
  "guidance/secure-design-principles",
  // Shadow IT
  "guidance/shadow-it",
  // Backups
  "guidance/backing-up-your-data",
  // Home working
  "guidance/home-working",
  "guidance/video-conferencing-services-security-guidance-organisations",
  // DDoS
  "guidance/denial-of-service-dos-guidance-collection",
];

/**
 * Collection URLs — framework landing pages (CAF, Cyber Essentials, etc.)
 * We crawl these and their child pages for framework content.
 */
const COLLECTION_SEED_SLUGS: string[] = [
  "collection/cyber-assessment-framework",
  "collection/cyber-assessment-framework/caf-objective-a-managing-security-risk",
  "collection/cyber-assessment-framework/caf-objective-b-protecting-against-cyber-attack",
  "collection/cyber-assessment-framework/caf-objective-c-detecting-cyber-security-events",
  "collection/cyber-assessment-framework/caf-objective-d-minimising-the-impact-of-cyber-security-incidents",
  "collection/supply-chain-security",
  "collection/ransomware-resistant-backups",
  "collection/cloud",
  "collection/passwords",
  "collection/zero-trust",
  "collection/small-business-guide",
  "collection/developers-collection",
  "collection/mobile-device-guidance",
  "collection/end-user-device-security",
  "collection/nis-directive",
  "collection/incident-management",
  "collection/risk-management",
  "collection/building-a-security-operations-centre",
  "collection/10-steps-to-cyber-security",
  "collection/cyber-security-design-principles",
  "collection/email-security-and-anti-spoofing",
  "collection/transport-layer-security-tls",
];

/**
 * Alert / advisory seed URLs — pages listing security alerts.
 * We parse the listing page to discover individual alert URLs.
 */
const ALERT_LISTING_URLS: string[] = [
  "news?q=&sort=date%3Adesc&type=alert",
  "news?q=&sort=date%3Adesc&type=advisory",
  "news?q=&sort=date%3Adesc&type=threat+assessment",
];

/**
 * Report seed slugs — standalone NCSC reports.
 */
const REPORT_SEED_SLUGS: string[] = [
  "report/annual-review-2024",
  "report/annual-review-2023",
  "report/impact-of-ai-on-cyber-threat",
  "report/ransomware-extortion-and-the-cyber-crime-ecosystem",
];

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchPage(url: string, retries = MAX_RETRIES): Promise<string | null> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      const res = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-GB,en;q=0.9",
        },
        signal: controller.signal,
        redirect: "follow",
      });

      clearTimeout(timeout);

      if (res.status === 404) {
        console.warn(`  [404] ${url}`);
        return null;
      }

      if (res.status === 429 || res.status >= 500) {
        const wait = RETRY_BACKOFF_MS * attempt;
        console.warn(`  [${res.status}] ${url} — retrying in ${wait}ms (attempt ${attempt}/${retries})`);
        await sleep(wait);
        continue;
      }

      if (!res.ok) {
        console.warn(`  [${res.status}] ${url} — skipping`);
        return null;
      }

      return await res.text();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (attempt < retries) {
        const wait = RETRY_BACKOFF_MS * attempt;
        console.warn(`  [ERR] ${url} — ${msg} — retrying in ${wait}ms (attempt ${attempt}/${retries})`);
        await sleep(wait);
      } else {
        console.error(`  [FAIL] ${url} — ${msg} — giving up after ${retries} attempts`);
        return null;
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Sitemap discovery — fallback for finding additional URLs
// ---------------------------------------------------------------------------

async function discoverFromSitemap(): Promise<{
  guidance: string[];
  collections: string[];
  news: string[];
  reports: string[];
  blogPosts: string[];
}> {
  const result = {
    guidance: [] as string[],
    collections: [] as string[],
    news: [] as string[],
    reports: [] as string[],
    blogPosts: [] as string[],
  };

  console.log("Discovering URLs from sitemap...");

  // The NCSC sitemap is an index pointing to paginated sitemaps
  const indexHtml = await fetchPage(`${BASE}/sitemap.xml`);
  if (!indexHtml) return result;

  await sleep(RATE_MS);

  // Extract sitemap page URLs from the index
  const sitemapPageUrls: string[] = [];
  const locRegex = /<loc>(.*?)<\/loc>/g;
  let match: RegExpExecArray | null;
  while ((match = locRegex.exec(indexHtml)) !== null) {
    const loc = match[1];
    if (loc) sitemapPageUrls.push(loc);
  }

  for (const sitemapUrl of sitemapPageUrls) {
    const pageHtml = await fetchPage(sitemapUrl);
    if (!pageHtml) continue;
    await sleep(RATE_MS);

    // Extract all <loc> URLs from this sitemap page
    const urlRegex = /<loc>(.*?)<\/loc>/g;
    let urlMatch: RegExpExecArray | null;
    while ((urlMatch = urlRegex.exec(pageHtml)) !== null) {
      const url = urlMatch[1];
      if (!url) continue;

      // Classify by path prefix
      const path = url.replace(BASE, "").replace(/^\//, "");
      if (path.startsWith("guidance/")) {
        result.guidance.push(path);
      } else if (path.startsWith("collection/")) {
        result.collections.push(path);
      } else if (path.startsWith("news/")) {
        result.news.push(path);
      } else if (path.startsWith("report/")) {
        result.reports.push(path);
      } else if (path.startsWith("blog-post/")) {
        result.blogPosts.push(path);
      }
    }
  }

  console.log(
    `  Sitemap discovery: ${result.guidance.length} guidance, ` +
      `${result.collections.length} collections, ${result.news.length} news, ` +
      `${result.reports.length} reports, ${result.blogPosts.length} blog posts`,
  );

  return result;
}

// ---------------------------------------------------------------------------
// Alert / advisory listing parser
// ---------------------------------------------------------------------------

async function discoverAlertUrls(): Promise<string[]> {
  const alertPaths: string[] = [];

  for (const listingPath of ALERT_LISTING_URLS) {
    const url = `${BASE}/${listingPath}`;
    console.log(`  Fetching alert listing: ${url}`);
    const html = await fetchPage(url);
    if (!html) continue;
    await sleep(RATE_MS);

    const $ = cheerio.load(html);

    // NCSC news listing pages contain links to individual articles
    $('a[href*="/news/"]').each((_i, el) => {
      const href = $(el).attr("href");
      if (!href) return;
      const path = href.replace(BASE, "").replace(/^\//, "");
      if (path.startsWith("news/") && !path.includes("?") && !alertPaths.includes(path)) {
        alertPaths.push(path);
      }
    });

    // Also check for /alert/ paths if they exist
    $('a[href*="/alert/"]').each((_i, el) => {
      const href = $(el).attr("href");
      if (!href) return;
      const path = href.replace(BASE, "").replace(/^\//, "");
      if (!alertPaths.includes(path)) {
        alertPaths.push(path);
      }
    });
  }

  console.log(`  Discovered ${alertPaths.length} alert/advisory URLs from listings`);
  return alertPaths;
}

// ---------------------------------------------------------------------------
// HTML parsing — guidance & collection pages
// ---------------------------------------------------------------------------

interface ParsedGuidance {
  reference: string;
  title: string;
  date: string | null;
  type: string;
  series: string;
  summary: string;
  fullText: string;
  topics: string[];
}

function slugToReference(slug: string): string {
  // Convert URL slug to a reference ID
  // e.g. "guidance/cyber-essentials-overview" -> "NCSC-cyber-essentials-overview"
  const cleaned = slug
    .replace(/^guidance\//, "")
    .replace(/^collection\//, "")
    .replace(/^report\//, "")
    .replace(/^news\//, "")
    .replace(/^blog-post\//, "");
  return `NCSC-${cleaned}`;
}

function classifyType(slug: string, $: cheerio.CheerioAPI): string {
  const lowerSlug = slug.toLowerCase();
  if (lowerSlug.includes("cyber-essentials")) return "framework";
  if (lowerSlug.includes("caf-") || lowerSlug.includes("cyber-assessment")) return "framework";
  if (lowerSlug.includes("10-steps")) return "guidance";
  if (lowerSlug.includes("board") || lowerSlug.includes("governance")) return "board";
  if (
    lowerSlug.includes("cloud-security-principle") ||
    lowerSlug.includes("secure-development") ||
    lowerSlug.includes("tls") ||
    lowerSlug.includes("penetration") ||
    lowerSlug.includes("code-signing") ||
    lowerSlug.includes("logging") ||
    lowerSlug.includes("vulnerability") ||
    lowerSlug.includes("device-security") ||
    lowerSlug.includes("network-security") ||
    lowerSlug.includes("email-security")
  ) {
    return "technical";
  }

  // Check page content for classification hints
  const text = $.text().toLowerCase();
  if (text.includes("technical guidance") || text.includes("implementation")) return "technical";
  if (text.includes("board") || text.includes("senior leadership")) return "board";
  if (text.includes("framework") || text.includes("certification")) return "framework";

  return "guidance";
}

function classifySeries(slug: string, title: string): string {
  const lower = (slug + " " + title).toLowerCase();
  if (lower.includes("cyber-essentials") || lower.includes("cyber essentials")) return "Cyber Essentials";
  if (lower.includes("10-steps") || lower.includes("10 steps")) return "10 Steps";
  if (lower.includes("caf") || lower.includes("cyber-assessment") || lower.includes("cyber assessment")) return "CAF";
  return "NCSC";
}

function extractTopics($: cheerio.CheerioAPI): string[] {
  const topics: string[] = [];

  // Look for topic tags/links on the page
  $('a[href*="/all-topics/"]').each((_i, el) => {
    const href = $(el).attr("href") ?? "";
    const topic = href.split("/all-topics/").pop()?.replace(/\/$/, "");
    if (topic && !topics.includes(topic)) {
      topics.push(topic);
    }
  });

  // Look for meta keywords
  const metaKeywords = $('meta[name="keywords"]').attr("content");
  if (metaKeywords) {
    for (const kw of metaKeywords.split(",")) {
      const t = kw.trim().toLowerCase().replace(/\s+/g, "-");
      if (t && !topics.includes(t)) {
        topics.push(t);
      }
    }
  }

  return topics;
}

function extractMainContent($: cheerio.CheerioAPI): string {
  // Remove nav, header, footer, script, style elements
  $("nav, header, footer, script, style, noscript, .cookie-banner, .breadcrumb, .sidebar").remove();

  // Try common NCSC content selectors
  const selectors = [
    "article",
    '[role="main"]',
    "main",
    ".main-content",
    ".page-content",
    ".article-content",
    ".guidance-content",
    "#main-content",
  ];

  for (const sel of selectors) {
    const el = $(sel);
    if (el.length > 0) {
      const text = el.text().replace(/\s+/g, " ").trim();
      if (text.length > 100) return text;
    }
  }

  // Fallback: extract from body
  const bodyText = $("body").text().replace(/\s+/g, " ").trim();
  return bodyText;
}

function extractSummary($: cheerio.CheerioAPI, fullText: string): string {
  // Try meta description
  const metaDesc =
    $('meta[name="description"]').attr("content") ??
    $('meta[property="og:description"]').attr("content");
  if (metaDesc && metaDesc.length > 30) return metaDesc.trim();

  // Try lead paragraph
  const lead = $("article p:first-of-type, .lead, .summary, .introduction p:first-of-type");
  if (lead.length > 0) {
    const text = lead.first().text().trim();
    if (text.length > 30) return text;
  }

  // Fallback: first 300 chars of full text
  if (fullText.length > 300) {
    return fullText.slice(0, 300).replace(/\s+\S*$/, "") + "...";
  }
  return fullText;
}

function extractDate($: cheerio.CheerioAPI): string | null {
  // <time> element
  const timeEl = $("time[datetime]");
  if (timeEl.length > 0) {
    const dt = timeEl.first().attr("datetime");
    if (dt) {
      // Parse ISO date or extract YYYY-MM-DD
      const match = /(\d{4}-\d{2}-\d{2})/.exec(dt);
      if (match?.[1]) return match[1];
    }
  }

  // Look for date in meta tags
  const metaDate =
    $('meta[name="date"]').attr("content") ??
    $('meta[property="article:published_time"]').attr("content") ??
    $('meta[name="dcterms.date"]').attr("content");
  if (metaDate) {
    const match = /(\d{4}-\d{2}-\d{2})/.exec(metaDate);
    if (match?.[1]) return match[1];
  }

  // Look for date pattern in page text (Published: DD Month YYYY)
  const text = $("body").text();
  const datePatterns = [
    /Published[:\s]+(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})/i,
    /Updated[:\s]+(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})/i,
    /(\d{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(\d{4})/i,
  ];

  const months: Record<string, string> = {
    january: "01", february: "02", march: "03", april: "04",
    may: "05", june: "06", july: "07", august: "08",
    september: "09", october: "10", november: "11", december: "12",
  };

  for (const pat of datePatterns) {
    const m = pat.exec(text);
    if (m?.[1] && m[2] && m[3]) {
      const day = m[1].padStart(2, "0");
      const month = months[m[2].toLowerCase()];
      if (month) return `${m[3]}-${month}-${day}`;
    }
  }

  return null;
}

function parseGuidancePage(slug: string, html: string): ParsedGuidance | null {
  const $ = cheerio.load(html);

  // Extract title
  const title =
    $("h1").first().text().trim() ||
    $('meta[property="og:title"]').attr("content")?.trim() ||
    "";

  if (!title) {
    console.warn(`  No title found for ${slug} — skipping`);
    return null;
  }

  const fullText = extractMainContent($);
  if (fullText.length < 50) {
    console.warn(`  Content too short for ${slug} (${fullText.length} chars) — skipping`);
    return null;
  }

  const reference = slugToReference(slug);
  const date = extractDate($);
  const type = classifyType(slug, $);
  const series = classifySeries(slug, title);
  const summary = extractSummary($, fullText);
  const topics = extractTopics($);

  return {
    reference,
    title,
    date,
    type,
    series,
    summary,
    fullText,
    topics,
  };
}

// ---------------------------------------------------------------------------
// HTML parsing — advisory / alert pages
// ---------------------------------------------------------------------------

interface ParsedAdvisory {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affectedProducts: string[];
  summary: string;
  fullText: string;
  cveReferences: string[];
}

function extractSeverity($: cheerio.CheerioAPI, text: string): string | null {
  // Look for severity indicators
  const lowerText = text.toLowerCase();
  if (lowerText.includes("critical severity") || lowerText.includes("severity: critical")) return "critical";
  if (lowerText.includes("high severity") || lowerText.includes("severity: high")) return "high";
  if (lowerText.includes("medium severity") || lowerText.includes("severity: medium")) return "medium";
  if (lowerText.includes("low severity") || lowerText.includes("severity: low")) return "low";

  // Check for CVSS score mentions to infer severity
  const cvssMatch = /CVSS\s*(?:v\d(?:\.\d)?\s*)?(?:score)?[:\s]+(\d+(?:\.\d+)?)/i.exec(text);
  if (cvssMatch?.[1]) {
    const score = parseFloat(cvssMatch[1]);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }

  // Check page badges/labels
  const badge = $(".severity, .alert-level, .threat-level").text().toLowerCase();
  if (badge.includes("critical")) return "critical";
  if (badge.includes("high")) return "high";
  if (badge.includes("medium")) return "medium";
  if (badge.includes("low")) return "low";

  return null;
}

function extractCves(text: string): string[] {
  const cves: string[] = [];
  const cveRegex = /CVE-\d{4}-\d{4,}/g;
  let match: RegExpExecArray | null;
  while ((match = cveRegex.exec(text)) !== null) {
    if (match[0] && !cves.includes(match[0])) {
      cves.push(match[0]);
    }
  }
  return cves;
}

function extractAffectedProducts($: cheerio.CheerioAPI, text: string): string[] {
  const products: string[] = [];

  // Look for "Affected products" or "Affected software" section
  const sections = text.split(/(?:Affected (?:products?|software|systems?|platforms?|versions?))[:\s]*/i);
  if (sections.length > 1 && sections[1]) {
    // Take the first paragraph after "Affected products"
    const para = sections[1].split(/\n\n|\.\s/)[0];
    if (para) {
      // Split by commas, semicolons, or "and"
      const items = para.split(/[,;]|\band\b/);
      for (const item of items) {
        const trimmed = item.trim();
        if (trimmed.length > 2 && trimmed.length < 100) {
          products.push(trimmed);
        }
      }
    }
  }

  return products.slice(0, 20); // Cap at 20
}

function parseAdvisoryPage(slug: string, html: string): ParsedAdvisory | null {
  const $ = cheerio.load(html);

  const title =
    $("h1").first().text().trim() ||
    $('meta[property="og:title"]').attr("content")?.trim() ||
    "";

  if (!title) {
    console.warn(`  No title found for advisory ${slug} — skipping`);
    return null;
  }

  const fullText = extractMainContent($);
  if (fullText.length < 30) {
    console.warn(`  Content too short for advisory ${slug} (${fullText.length} chars) — skipping`);
    return null;
  }

  const reference = slugToReference(slug);
  const date = extractDate($);
  const severity = extractSeverity($, fullText);
  const summary = extractSummary($, fullText);
  const cveReferences = extractCves(fullText);
  const affectedProducts = extractAffectedProducts($, fullText);

  return {
    reference,
    title,
    date,
    severity,
    summary,
    fullText,
    cveReferences,
    affectedProducts,
  };
}

// ---------------------------------------------------------------------------
// Database operations
// ---------------------------------------------------------------------------

function openDb(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  return db;
}

function getExistingReferences(db: Database.Database): Set<string> {
  const refs = new Set<string>();
  const guidanceRefs = db.prepare("SELECT reference FROM guidance").all() as { reference: string }[];
  for (const r of guidanceRefs) refs.add(r.reference);
  const advisoryRefs = db.prepare("SELECT reference FROM advisories").all() as { reference: string }[];
  for (const r of advisoryRefs) refs.add(r.reference);
  return refs;
}

function upsertGuidance(db: Database.Database, g: ParsedGuidance): void {
  db.prepare(`
    INSERT INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'current')
    ON CONFLICT(reference) DO UPDATE SET
      title     = excluded.title,
      title_en  = excluded.title_en,
      date      = excluded.date,
      type      = excluded.type,
      series    = excluded.series,
      summary   = excluded.summary,
      full_text = excluded.full_text,
      topics    = excluded.topics,
      status    = excluded.status
  `).run(
    g.reference,
    g.title,
    g.title,  // title_en = title (English content)
    g.date,
    g.type,
    g.series,
    g.summary,
    g.fullText,
    JSON.stringify(g.topics),
  );
}

function upsertAdvisory(db: Database.Database, a: ParsedAdvisory): void {
  db.prepare(`
    INSERT INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(reference) DO UPDATE SET
      title             = excluded.title,
      date              = excluded.date,
      severity          = excluded.severity,
      affected_products = excluded.affected_products,
      summary           = excluded.summary,
      full_text         = excluded.full_text,
      cve_references    = excluded.cve_references
  `).run(
    a.reference,
    a.title,
    a.date,
    a.severity,
    JSON.stringify(a.affectedProducts),
    a.summary,
    a.fullText,
    JSON.stringify(a.cveReferences),
  );
}

function upsertFramework(db: Database.Database, id: string, name: string, description: string, count: number): void {
  db.prepare(`
    INSERT INTO frameworks (id, name, name_en, description, document_count)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET
      name           = excluded.name,
      name_en        = excluded.name_en,
      description    = excluded.description,
      document_count = excluded.document_count
  `).run(id, name, name, description, count);
}

// ---------------------------------------------------------------------------
// Main crawl logic
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("=== NCSC Ingestion Crawler ===");
  console.log(`  DB path:   ${DB_PATH}`);
  console.log(`  Rate:      ${RATE_MS}ms`);
  console.log(`  Dry run:   ${DRY_RUN}`);
  console.log(`  Resume:    ${RESUME}`);
  console.log(`  Force:     ${FORCE}`);
  console.log("");

  const db = DRY_RUN ? null : openDb();
  const existingRefs = db ? getExistingReferences(db) : new Set<string>();

  const stats = {
    guidanceFetched: 0,
    guidanceParsed: 0,
    guidanceInserted: 0,
    guidanceSkipped: 0,
    advisoryFetched: 0,
    advisoryParsed: 0,
    advisoryInserted: 0,
    advisorySkipped: 0,
    errors: 0,
  };

  // ----- Phase 1: Discover additional URLs from sitemap -----
  console.log("--- Phase 1: Sitemap discovery ---");
  const discovered = await discoverFromSitemap();
  await sleep(RATE_MS);

  // Merge sitemap-discovered URLs with curated seed lists (curated takes priority)
  const allGuidanceSlugs = [...new Set([...GUIDANCE_SEED_SLUGS, ...discovered.guidance])];
  const allCollectionSlugs = [...new Set([...COLLECTION_SEED_SLUGS, ...discovered.collections])];
  const allReportSlugs = [...new Set([...REPORT_SEED_SLUGS, ...discovered.reports])];

  console.log(`  Total guidance URLs: ${allGuidanceSlugs.length}`);
  console.log(`  Total collection URLs: ${allCollectionSlugs.length}`);
  console.log(`  Total report URLs: ${allReportSlugs.length}`);
  console.log("");

  // ----- Phase 2: Crawl guidance pages -----
  console.log("--- Phase 2: Crawling guidance pages ---");
  const frameworkCounts: Record<string, number> = {
    "Cyber Essentials": 0,
    "10 Steps": 0,
    CAF: 0,
    NCSC: 0,
  };

  for (const slug of allGuidanceSlugs) {
    const reference = slugToReference(slug);

    if (RESUME && existingRefs.has(reference)) {
      stats.guidanceSkipped++;
      continue;
    }

    const url = `${BASE}/${slug}`;
    console.log(`  Fetching: ${url}`);

    const html = await fetchPage(url);
    stats.guidanceFetched++;

    if (!html) {
      stats.errors++;
      await sleep(RATE_MS);
      continue;
    }

    const parsed = parseGuidancePage(slug, html);
    if (!parsed) {
      stats.errors++;
      await sleep(RATE_MS);
      continue;
    }

    stats.guidanceParsed++;
    frameworkCounts[parsed.series] = (frameworkCounts[parsed.series] ?? 0) + 1;

    if (DRY_RUN) {
      console.log(`    [DRY] ${parsed.reference} — ${parsed.title} (${parsed.type}/${parsed.series}, ${parsed.fullText.length} chars)`);
    } else if (db) {
      upsertGuidance(db, parsed);
      stats.guidanceInserted++;
      console.log(`    [OK] ${parsed.reference} — ${parsed.title}`);
    }

    await sleep(RATE_MS);
  }

  // ----- Phase 3: Crawl collection pages (treated as guidance) -----
  console.log("\n--- Phase 3: Crawling collection pages ---");

  for (const slug of allCollectionSlugs) {
    const reference = slugToReference(slug);

    if (RESUME && existingRefs.has(reference)) {
      stats.guidanceSkipped++;
      continue;
    }

    const url = `${BASE}/${slug}`;
    console.log(`  Fetching: ${url}`);

    const html = await fetchPage(url);
    stats.guidanceFetched++;

    if (!html) {
      stats.errors++;
      await sleep(RATE_MS);
      continue;
    }

    const parsed = parseGuidancePage(slug, html);
    if (!parsed) {
      stats.errors++;
      await sleep(RATE_MS);
      continue;
    }

    stats.guidanceParsed++;
    frameworkCounts[parsed.series] = (frameworkCounts[parsed.series] ?? 0) + 1;

    if (DRY_RUN) {
      console.log(`    [DRY] ${parsed.reference} — ${parsed.title} (${parsed.type}/${parsed.series}, ${parsed.fullText.length} chars)`);
    } else if (db) {
      upsertGuidance(db, parsed);
      stats.guidanceInserted++;
      console.log(`    [OK] ${parsed.reference} — ${parsed.title}`);
    }

    // Also discover child links from collection pages
    const $c = cheerio.load(html);
    $c('a[href*="/guidance/"], a[href*="/collection/"]').each((_i, el) => {
      const href = $c(el).attr("href");
      if (!href) return;
      const path = href.replace(BASE, "").replace(/^\//, "");
      if (
        (path.startsWith("guidance/") || path.startsWith("collection/")) &&
        !path.includes("?") &&
        !allGuidanceSlugs.includes(path) &&
        !allCollectionSlugs.includes(path)
      ) {
        allGuidanceSlugs.push(path);
      }
    });

    await sleep(RATE_MS);
  }

  // ----- Phase 4: Crawl report pages (treated as guidance) -----
  console.log("\n--- Phase 4: Crawling report pages ---");

  for (const slug of allReportSlugs) {
    const reference = slugToReference(slug);

    if (RESUME && existingRefs.has(reference)) {
      stats.guidanceSkipped++;
      continue;
    }

    const url = `${BASE}/${slug}`;
    console.log(`  Fetching: ${url}`);

    const html = await fetchPage(url);
    stats.guidanceFetched++;

    if (!html) {
      stats.errors++;
      await sleep(RATE_MS);
      continue;
    }

    const parsed = parseGuidancePage(slug, html);
    if (!parsed) {
      stats.errors++;
      await sleep(RATE_MS);
      continue;
    }

    stats.guidanceParsed++;

    if (DRY_RUN) {
      console.log(`    [DRY] ${parsed.reference} — ${parsed.title} (${parsed.type}/${parsed.series}, ${parsed.fullText.length} chars)`);
    } else if (db) {
      upsertGuidance(db, parsed);
      stats.guidanceInserted++;
      console.log(`    [OK] ${parsed.reference} — ${parsed.title}`);
    }

    await sleep(RATE_MS);
  }

  // ----- Phase 5: Discover and crawl advisories/alerts -----
  console.log("\n--- Phase 5: Crawling advisories and alerts ---");

  const alertSlugs = await discoverAlertUrls();
  await sleep(RATE_MS);

  // Also add news items discovered from sitemap that look like alerts
  const sitemapAlerts = discovered.news.filter((slug) => {
    const lower = slug.toLowerCase();
    return (
      lower.includes("vulnerabilit") ||
      lower.includes("exploit") ||
      lower.includes("ransomware") ||
      lower.includes("advisory") ||
      lower.includes("alert") ||
      lower.includes("patch") ||
      lower.includes("cve") ||
      lower.includes("threat") ||
      lower.includes("malware") ||
      lower.includes("attack")
    );
  });

  const allAlertSlugs = [...new Set([...alertSlugs, ...sitemapAlerts])];
  console.log(`  Total advisory/alert URLs to crawl: ${allAlertSlugs.length}`);

  for (const slug of allAlertSlugs) {
    const reference = slugToReference(slug);

    if (RESUME && existingRefs.has(reference)) {
      stats.advisorySkipped++;
      continue;
    }

    const url = `${BASE}/${slug}`;
    console.log(`  Fetching: ${url}`);

    const html = await fetchPage(url);
    stats.advisoryFetched++;

    if (!html) {
      stats.errors++;
      await sleep(RATE_MS);
      continue;
    }

    const parsed = parseAdvisoryPage(slug, html);
    if (!parsed) {
      stats.errors++;
      await sleep(RATE_MS);
      continue;
    }

    stats.advisoryParsed++;

    if (DRY_RUN) {
      console.log(
        `    [DRY] ${parsed.reference} — ${parsed.title} ` +
          `(severity=${parsed.severity ?? "unknown"}, CVEs=${parsed.cveReferences.length}, ${parsed.fullText.length} chars)`,
      );
    } else if (db) {
      upsertAdvisory(db, parsed);
      stats.advisoryInserted++;
      console.log(`    [OK] ${parsed.reference} — ${parsed.title}`);
    }

    await sleep(RATE_MS);
  }

  // ----- Phase 6: Update framework records -----
  console.log("\n--- Phase 6: Updating framework records ---");

  if (!DRY_RUN && db) {
    // Count actual documents per series
    const seriesCounts = db
      .prepare("SELECT series, COUNT(*) as cnt FROM guidance GROUP BY series")
      .all() as { series: string; cnt: number }[];

    const countMap = new Map<string, number>();
    for (const row of seriesCounts) {
      countMap.set(row.series, row.cnt);
    }

    upsertFramework(
      db,
      "cyber-essentials",
      "Cyber Essentials",
      "UK government-backed scheme defining five technical controls for cyber security: firewalls, secure configuration, user access control, malware protection, and patch management. Includes Cyber Essentials Plus with independent technical verification.",
      countMap.get("Cyber Essentials") ?? 0,
    );

    upsertFramework(
      db,
      "10-steps",
      "10 Steps to Cyber Security",
      "NCSC foundational guidance covering ten areas: risk management, engagement and training, asset management, architecture and configuration, vulnerability management, identity and access management, data security, logging and monitoring, incident management, and supply chain security.",
      countMap.get("10 Steps") ?? 0,
    );

    upsertFramework(
      db,
      "caf",
      "Cyber Assessment Framework (CAF)",
      "Systematic approach to assessing cyber risk management for operators of essential services under the NIS Regulations. Four objectives: Managing Security Risk, Protecting Against Cyber Attack, Detecting Cyber Security Events, Minimising Impact.",
      countMap.get("CAF") ?? 0,
    );

    upsertFramework(
      db,
      "ncsc-general",
      "NCSC General Guidance",
      "General NCSC guidance covering cloud security, zero trust, supply chain, board-level responsibilities, secure development, logging, vulnerability disclosure, and operational technology security.",
      countMap.get("NCSC") ?? 0,
    );

    console.log("  Frameworks updated.");
  } else {
    console.log("  [DRY] Would update 4 framework records");
  }

  // ----- Summary -----
  console.log("\n=== Ingestion Summary ===");
  console.log(`  Guidance fetched:    ${stats.guidanceFetched}`);
  console.log(`  Guidance parsed:     ${stats.guidanceParsed}`);
  console.log(`  Guidance inserted:   ${stats.guidanceInserted}`);
  console.log(`  Guidance skipped:    ${stats.guidanceSkipped} (already in DB)`);
  console.log(`  Advisories fetched:  ${stats.advisoryFetched}`);
  console.log(`  Advisories parsed:   ${stats.advisoryParsed}`);
  console.log(`  Advisories inserted: ${stats.advisoryInserted}`);
  console.log(`  Advisories skipped:  ${stats.advisorySkipped} (already in DB)`);
  console.log(`  Errors:              ${stats.errors}`);

  if (db) {
    const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
    const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
    const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;

    console.log(`\n  Database totals:`);
    console.log(`    Frameworks:  ${frameworkCount}`);
    console.log(`    Guidance:    ${guidanceCount}`);
    console.log(`    Advisories:  ${advisoryCount}`);

    db.close();
  }

  console.log(`\nDone.`);
}

main().catch((err) => {
  console.error(`Fatal: ${err instanceof Error ? err.message : String(err)}`);
  if (err instanceof Error && err.stack) {
    console.error(err.stack);
  }
  process.exit(1);
});
