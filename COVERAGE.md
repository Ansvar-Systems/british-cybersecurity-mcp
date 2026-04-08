# Coverage

This MCP covers cybersecurity guidance and advisories published by the UK National Cyber Security Centre (NCSC).

## Corpus Scope

| Source | Description | Coverage |
|--------|-------------|----------|
| **Cyber Essentials** | UK government certification scheme requirements and controls | Full scheme requirements |
| **10 Steps to Cyber Security** | NCSC foundational security framework for organisations | All 10 steps guidance |
| **Cyber Assessment Framework (CAF)** | 14 principles, 39 contributing outcomes for critical infrastructure operators | Full CAF v3.2 |
| **NCSC Security Advisories** | CVE-tagged threat advisories with severity ratings and affected products | Subset of published advisories |
| **Board-level Guidance** | NCSC guidance for boards and senior leadership | Selected publications |
| **NIS Regulations 2018** | Network and information systems security requirements | Reference material |

## Known Gaps

- **Periodic snapshots**: Database is updated periodically and may lag official NCSC publications by days or weeks
- **No real-time updates**: Advisories published after the last ingest are not included; use `gb_cyber_check_data_freshness` to see current counts
- **Partial advisory coverage**: Not all historical advisories are ingested; focus is on recent and high-severity publications
- **Draft guidance**: Draft and consultation documents may be excluded
- **Archived content**: Superseded documents may not be fully represented
- **Third-party frameworks**: Content from NCSC partners (NCSC-certified schemes, CESG, etc.) is not included unless republished by NCSC

## Data Authority

All content is sourced from official NCSC publications at [ncsc.gov.uk](https://www.ncsc.gov.uk/).
Data is reproduced under the [Open Government Licence v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/).

## Freshness

Use the `gb_cyber_check_data_freshness` tool to query current document counts in the database.
Use `gb_cyber_list_sources` for source URLs and ingestion metadata.
