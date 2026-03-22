/**
 * Seed the NCSC database with sample guidance documents, advisories, and
 * frameworks for testing.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["NCSC_DB_PATH"] ?? "data/ncsc.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) {
  mkdirSync(dir, { recursive: true });
}

if (force && existsSync(DB_PATH)) {
  unlinkSync(DB_PATH);
  console.log(`Deleted existing database at ${DB_PATH}`);
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);

console.log(`Database initialised at ${DB_PATH}`);

// --- Frameworks --------------------------------------------------------------

interface FrameworkRow {
  id: string;
  name: string;
  name_en: string;
  description: string;
  document_count: number;
}

const frameworks: FrameworkRow[] = [
  {
    id: "cyber-essentials",
    name: "Cyber Essentials",
    name_en: "Cyber Essentials",
    description: "Cyber Essentials is a UK government-backed scheme that helps organisations protect themselves against common cyber attacks. The scheme defines five technical controls: firewalls, secure configuration, user access control, malware protection, and patch management.",
    document_count: 2,
  },
  {
    id: "10-steps",
    name: "10 Steps to Cyber Security",
    name_en: "10 Steps to Cyber Security",
    description: "The NCSC 10 Steps to Cyber Security provides guidance for organisations on how to protect themselves in cyberspace. Covers network security, user education, malware prevention, and incident management.",
    document_count: 1,
  },
  {
    id: "caf",
    name: "Cyber Assessment Framework (CAF)",
    name_en: "Cyber Assessment Framework",
    description: "The CAF provides a systematic approach to assessing cyber risk management for operators of essential services under the NIS Regulations. Used by UK regulators and competent authorities.",
    document_count: 1,
  },
];

const insertFramework = db.prepare(
  "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)",
);

for (const f of frameworks) {
  insertFramework.run(f.id, f.name, f.name_en, f.description, f.document_count);
}

console.log(`Inserted ${frameworks.length} frameworks`);

// --- Guidance ----------------------------------------------------------------

interface GuidanceRow {
  reference: string;
  title: string;
  title_en: string;
  date: string;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string;
  status: string;
}

const guidance: GuidanceRow[] = [
  {
    reference: "NCSC-CE-2024",
    title: "Cyber Essentials Requirements for IT Infrastructure",
    title_en: "Cyber Essentials Requirements for IT Infrastructure",
    date: "2024-01-22",
    type: "framework",
    series: "Cyber Essentials",
    summary: "The official technical requirements for Cyber Essentials certification. Defines five controls: boundary firewalls, secure configuration, access control, malware protection, and patch management. High/critical patches must be applied within 14 days.",
    full_text: "Cyber Essentials is a Government-backed scheme that helps organisations protect themselves against common online threats. Five technical controls: (1) Firewalls — all devices protected by a firewall blocking unnecessary connections. Boundary firewalls block by default and allow only approved connections. (2) Secure Configuration — computers and network devices configured to reduce vulnerabilities, change default passwords, disable unnecessary accounts and software. (3) User Access Control — user accounts managed carefully; standard accounts for routine activities, administrative accounts only for admin tasks, MFA required for privileged accounts and cloud services. (4) Malware Protection — anti-malware software installed and up to date on all computers; application sandboxing or allowlisting may be used as alternative. (5) Security Update Management — all software kept up to date, high/critical patches applied within 14 days, unsupported software removed.",
    topics: JSON.stringify(["firewall", "patch-management", "access-control", "malware", "configuration"]),
    status: "current",
  },
  {
    reference: "NCSC-CE-PLUS-2024",
    title: "Cyber Essentials Plus — Technical Verification Requirements",
    title_en: "Cyber Essentials Plus — Technical Verification Requirements",
    date: "2024-01-22",
    type: "framework",
    series: "Cyber Essentials",
    summary: "Technical verification requirements for Cyber Essentials Plus certification. Includes vulnerability scanning, authenticated device testing, email and browser malware testing, and MFA verification by an independent assessor.",
    full_text: "Cyber Essentials Plus requires hands-on technical verification by an independent assessor. Verification process: (1) Vulnerability scanning of external-facing infrastructure; (2) Internal network scanning for unpatched or misconfigured devices; (3) Authenticated scanning of minimum five end-user devices to check patch levels and configuration; (4) Email testing — simulated phishing emails with common file types to verify malware protection prevents execution; (5) Web browser testing to verify the browser does not allow download and execution of malicious software; (6) Multi-factor authentication verification for cloud services and privileged accounts. Plus certification valid for 12 months from assessment date.",
    topics: JSON.stringify(["vulnerability-scanning", "penetration-testing", "certification", "MFA"]),
    status: "current",
  },
  {
    reference: "NCSC-10STEPS-2023",
    title: "10 Steps to Cyber Security",
    title_en: "10 Steps to Cyber Security",
    date: "2023-09-01",
    type: "guidance",
    series: "10 Steps",
    summary: "NCSC foundational guidance covering ten areas: risk management, engagement and training, asset management, architecture and configuration, vulnerability management, identity and access management, data security, logging and monitoring, incident management, and supply chain security.",
    full_text: "10 Steps to Cyber Security covers ten critical areas: (1) Risk Management — understand and prioritise cyber risks, establish a framework, document and review regularly; (2) Engagement and Training — build skills, run cybersecurity awareness training, ensure staff understand responsibilities; (3) Asset Management — maintain inventory of hardware/software, understand data sensitivity; (4) Architecture and Configuration — apply network segmentation, use secure-by-default configurations; (5) Vulnerability Management — apply patches rapidly (prioritise critical/high), use vulnerability scanning; (6) Identity and Access Management — strong authentication including MFA for privileged access, principle of least privilege; (7) Data Security — encrypt sensitive data, know where it is stored; (8) Logging and Monitoring — maintain audit logs covering authentication, access, admin actions; (9) Incident Management — develop and test incident response plan, clear roles and responsibilities; (10) Supply Chain Security — understand dependencies, include security in supplier contracts.",
    topics: JSON.stringify(["risk-management", "training", "asset-management", "vulnerability", "access-control", "incident-response"]),
    status: "current",
  },
  {
    reference: "NCSC-CAF-3.2",
    title: "Cyber Assessment Framework (CAF) v3.2",
    title_en: "Cyber Assessment Framework v3.2",
    date: "2023-06-01",
    type: "framework",
    series: "CAF",
    summary: "CAF provides a systematic approach to assessing cyber risk management for operators of essential services under the NIS Regulations. Version 3.2 includes 14 objectives in four goals: A (Managing Security Risk), B (Protecting Against Cyber Attack), C (Detecting Cyber Security Events), D (Minimising Impact).",
    full_text: "The Cyber Assessment Framework (CAF) v3.2 provides a systematic approach to assessing cyber risks to essential services. Used by UK competent authorities under the NIS Regulations 2018. Four top-level goals: (A) Managing Security Risk — governance, risk management, asset management, supply chain; (B) Protecting Against Cyber Attack — service protection policies, identity and access control, data security, system security, resilient networks, staff awareness and training; (C) Detecting Cyber Security Events — security monitoring and anomaly detection; (D) Minimising the Impact of Cyber Security Incidents — response and recovery planning, improvements, communication. Each objective includes Contributing Outcomes with Indicators of Good Practice (IGPs). CAF is a framework for continuous improvement, not a compliance checklist.",
    topics: JSON.stringify(["nis-regulations", "risk-management", "essential-services", "governance"]),
    status: "current",
  },
  {
    reference: "NCSC-BOARD-2023",
    title: "Cyber Security: A Board-Level Responsibility",
    title_en: "Cyber Security: A Board-Level Responsibility",
    date: "2023-03-14",
    type: "board",
    series: "NCSC",
    summary: "NCSC guidance for boards on their role in cybersecurity. Covers six questions boards should ask: understanding exposure, prioritising cyber risk, assigning accountability, ensuring investment, assessing supplier risk, and planning for incidents.",
    full_text: "Six questions for boards: (1) How do you understand and manage your cyber security exposure? Boards should understand the most significant cyber risks and how they are managed. (2) How does cyber risk feature in your risk management approach? Cyber risk should be treated like other significant business risks, with risk appetite set at board level. (3) Who is accountable for cyber security? Clear accountability at senior level with known reporting lines to the board. (4) How do you ensure sufficient investment? Budget commensurate with risks faced, understood by the board. (5) How do you manage the cyber risks in your supply chain? Understand which suppliers have access to critical systems and what security requirements apply. (6) How will you respond to a significant cyber incident? Incident response plans exist, are tested, and senior leaders understand their roles.",
    topics: JSON.stringify(["board-governance", "risk-management", "accountability", "supply-chain"]),
    status: "current",
  },
  {
    reference: "NCSC-CLOUDSEC-2022",
    title: "Cloud Security Guidance — 14 Cloud Security Principles",
    title_en: "Cloud Security Guidance — 14 Cloud Security Principles",
    date: "2022-11-01",
    type: "technical",
    series: "NCSC",
    summary: "NCSC guidance on using cloud services securely. Covers 14 cloud security principles: data in transit protection, asset protection, separation between users, governance framework, operational security, personnel security, secure development, supply chain security, and identity and authentication.",
    full_text: "14 cloud security principles: (1) Data in transit protection; (2) Asset protection and resilience; (3) Separation between users; (4) Governance framework; (5) Operational security; (6) Personnel security; (7) Secure development; (8) Supply chain security; (9) Secure user management; (10) Identity and authentication — all service interfaces authenticated and authorised; (11) External interface protection; (12) Secure service administration — administrative access appropriately controlled; (13) Audit information for users — audit info needed to monitor access and changes; (14) Secure use of the service — insecure use can undermine security regardless of service security.",
    topics: JSON.stringify(["cloud-security", "data-protection", "access-control", "governance"]),
    status: "current",
  },
];

const insertGuidance = db.prepare(`
  INSERT OR IGNORE INTO guidance
    (reference, title, title_en, date, type, series, summary, full_text, topics, status)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertGuidanceAll = db.transaction(() => {
  for (const g of guidance) {
    insertGuidance.run(
      g.reference, g.title, g.title_en, g.date, g.type,
      g.series, g.summary, g.full_text, g.topics, g.status,
    );
  }
});

insertGuidanceAll();
console.log(`Inserted ${guidance.length} guidance documents`);

// --- Advisories --------------------------------------------------------------

interface AdvisoryRow {
  reference: string;
  title: string;
  date: string;
  severity: string;
  affected_products: string;
  summary: string;
  full_text: string;
  cve_references: string;
}

const advisories: AdvisoryRow[] = [
  {
    reference: "NCSC-ADV-2024-001",
    title: "Critical Vulnerability in Ivanti Connect Secure and Policy Secure",
    date: "2024-01-11",
    severity: "critical",
    affected_products: JSON.stringify(["Ivanti Connect Secure", "Ivanti Policy Secure"]),
    summary: "NCSC advises UK organisations to patch critical vulnerabilities in Ivanti Connect Secure and Policy Secure. CVE-2023-46805 (authentication bypass) and CVE-2024-21887 (command injection) are being actively exploited for unauthenticated remote code execution.",
    full_text: "Two critical vulnerabilities: CVE-2023-46805 (CVSS 8.2, authentication bypass) and CVE-2024-21887 (CVSS 9.1, command injection). Exploited together they allow unauthenticated remote code execution. State-sponsored actors exploiting these since December 2023. Successful exploitation enables lateral movement, credential theft, and data exfiltration. Affected: Ivanti Connect Secure 9.x and 22.x, Ivanti Policy Secure 22.x. Mitigations: apply patches immediately, perform factory reset if compromise suspected, review authentication logs, rotate all credentials. Report suspected compromises to the NCSC.",
    cve_references: JSON.stringify(["CVE-2023-46805", "CVE-2024-21887"]),
  },
  {
    reference: "NCSC-ADV-2023-005",
    title: "Royal Mail Ransomware Attack — LockBit Advisory",
    date: "2023-01-13",
    severity: "high",
    affected_products: JSON.stringify(["Royal Mail IT systems"]),
    summary: "Advisory following the LockBit ransomware attack on Royal Mail in January 2023, disrupting international services. NCSC worked with Royal Mail to restore services and advises organisations on defensive measures against LockBit.",
    full_text: "In January 2023, Royal Mail was attacked by LockBit, causing significant disruption to international export services. LockBit employs double extortion — encrypting victim data and threatening to publish stolen data unless ransom is paid. Initial access methods: exploiting unpatched vulnerabilities, phishing campaigns, compromised credentials from credential-stuffing or criminal forums. Defensive recommendations: keep all software patched (especially internet-facing systems), use MFA on all accounts and VPN access, implement network segmentation, maintain offline backups and test restoration, implement robust email security, have a tested incident response plan. Contact the NCSC if you suspect ransomware attack before paying any ransom.",
    cve_references: JSON.stringify([]),
  },
  {
    reference: "NCSC-ADV-2023-012",
    title: "MOVEit Transfer SQL Injection Vulnerability — Active Exploitation",
    date: "2023-06-01",
    severity: "critical",
    affected_products: JSON.stringify(["MOVEit Transfer", "MOVEit Cloud"]),
    summary: "Critical SQL injection vulnerability in MOVEit Transfer (CVE-2023-34362) being actively exploited by the Cl0p ransomware group to exfiltrate data from organisations worldwide including BBC, British Airways, and Boots.",
    full_text: "CVE-2023-34362 (CVSS 9.8) allows unauthenticated attackers to access MOVEit Transfer databases and exfiltrate data. The Cl0p group exploited hundreds of organisations across the UK, US, and Europe without deploying ransomware — instead threatening to publish stolen data. UK organisations affected include the BBC, British Airways, Boots, and Aer Lingus. Immediate actions: apply Progress Software patches, review all activity from at least May 27 2023, check for indicators of compromise (unauthorised file access, suspicious user accounts, unexpected data downloads), disable MOVEit HTTP/HTTPS traffic if patching not immediately possible, report compromises to NCSC, notify ICO if personal data breached.",
    cve_references: JSON.stringify(["CVE-2023-34362"]),
  },
];

const insertAdvisory = db.prepare(`
  INSERT OR IGNORE INTO advisories
    (reference, title, date, severity, affected_products, summary, full_text, cve_references)
  VALUES
    (?, ?, ?, ?, ?, ?, ?, ?)
`);

const insertAdvisoriesAll = db.transaction(() => {
  for (const a of advisories) {
    insertAdvisory.run(
      a.reference, a.title, a.date, a.severity,
      a.affected_products, a.summary, a.full_text, a.cve_references,
    );
  }
});

insertAdvisoriesAll();
console.log(`Inserted ${advisories.length} advisories`);

const guidanceCount = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const advisoryCount = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const frameworkCount = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;

console.log(`\nDatabase summary:`);
console.log(`  Frameworks:  ${frameworkCount}`);
console.log(`  Guidance:    ${guidanceCount}`);
console.log(`  Advisories:  ${advisoryCount}`);
console.log(`\nDone. Database ready at ${DB_PATH}`);

db.close();
