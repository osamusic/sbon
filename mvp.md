# SBON - SBOM Viewer for Non-Engineers

## Concept

A Japanese-first SBOM viewer designed for:

- Procurement teams
- Quality Assurance
- Regulatory teams
- Security managers
- Non-engineering stakeholders
- Organizations that need to review software supply chain risk

The goal is **not** to provide another developer-oriented SBOM scanner.

The goal is to make SBOMs:

- understandable
- explainable
- reviewable
- useful for operational decision making

---

# Background

Existing SBOM tools are mainly designed for:

- DevSecOps
- CI/CD pipelines
- Engineering teams
- Vulnerability scanning

However, real-world SBOM consumers are increasingly:

- procurement departments
- risk management teams
- regulatory reviewers
- product owners
- operations teams
- business stakeholders

Across regulated products, connected devices, enterprise software, and procurement workflows, cybersecurity is becoming part of purchasing and compliance requirements. Customers increasingly request SBOMs and security documentation during vendor and product reviews.

At the same time, most stakeholders cannot read:

- SPDX
- CycloneDX
- package trees
- CVE databases

This creates a major usability gap.

---

# Product Vision

## “SBOM that humans can understand”

Instead of showing raw JSON:

```json
{
  "name": "openssl",
  "version": "1.1.1w"
}
```

The system explains:

```text
OpenSSL

A widely used cryptographic library used to protect network communications.

Current Status:
- Support ended
- Known vulnerabilities exist
- Update recommended
```

---

# Target Users

## Primary

- Procurement teams
- Security governance teams
- QA / RA teams
- Product security teams
- Operations and risk management teams

## Secondary

- Device manufacturers
- Embedded device vendors
- Internal security teams
- Educational institutions

---

# Core Value

## 1. Japanese-readable SBOM

Translate technical OSS information into understandable Japanese explanations.

Examples:

- What is OpenSSL?
- Why is glibc important?
- Is BusyBox risky?

---

## 2. Risk-oriented visualization

Instead of only listing packages:

- End-of-support warnings
- Vulnerability severity
- Maintenance activity
- Long-term support concerns
- Regulatory impact

---

## 3. Business-oriented review

Highlight components related to:

- Cryptography
- Authentication
- Networking
- OTA updates
- Linux kernel
- Remote access

Potential future mapping:

- FDA Section 524B
- CRA
- NIS2
- Secure by Design concepts

---

## 4. Executive / procurement summaries

Example:

```text
This product contains 42 OSS components.

Findings:
- 3 unsupported components
- 2 high-risk vulnerabilities
- 8 outdated packages

Overall Risk:
Medium
```

---

# MVP Scope

## Phase 1

### Input

- CycloneDX JSON
- SPDX JSON

---

### Features

- Component list
- Dependency tree
- CVE display
- License display
- Package details
- Japanese explanation

---

### Basic Risk Indicators

- EOL warning
- Known vulnerabilities
- Outdated versions
- Unknown package metadata

---

### Export

- PDF report
- Excel export

(Important for Japanese enterprise workflows)

---

# Future Features

## Phase 2

### SBOM Diff Viewer

Compare:

- added packages
- removed packages
- updated versions

Useful for release reviews.

---

## Phase 3

### AI-assisted explanation

Examples:

- “Why is this component important?”
- “What is the business impact?”
- “Should non-engineering stakeholders care?”

---

## Phase 4

### Risk Dashboard

Examples:

- Device security score
- Long-term maintenance risk
- Unsupported OSS detection
- Supply chain visibility

---

# Differentiation

Most existing tools focus on:

- scanning
- CI/CD
- developer workflows

This product focuses on:

Human-readable SBOM review

Especially for:

- procurement
- governance
- compliance
- product security

---

# Technical Direction

## Frontend

- React
- Tailwind CSS

---

## Backend

- FastAPI

---

## Parsing Libraries

- CycloneDX Python library
- SPDX tools

---

## Database

- SQLite (initially)
- PostgreSQL (future)

---

# Branding

- SBON
- SBOM Viewer

---

# Strategic Potential

This project can evolve into:

- Software supply chain risk review platform
- CRA/FDA and other regulatory review support
- Security governance tooling
- Educational platform
- Procurement support system

It also aligns well with growing regulatory and procurement pressure around cybersecurity and software transparency.
