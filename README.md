# Domain Ownership Attribution Tool

## Overview
This project automates the investigation of domain ownership by correlating WHOIS, DNS, and ASN data. It is designed to support security engineers in identifying whether domains (e.g., from SPF records) are internally owned or belong to third parties.

---

## Problem Statement
In email security and vulnerability management, malformed or overly permissive SPF records often include multiple external domains. Determining whether these domains are trusted or third-party is a manual and time-consuming process.

---

## Solution
This tool automates domain attribution by:
- Extracting ownership signals from WHOIS data
- Analyzing DNS infrastructure (NS and MX records)
- Mapping domains to hosting providers using ASN lookup
- Correlating all signals to infer likely ownership

---

## Features
- WHOIS lookup (registrant, registrar, creation date)
- DNS analysis:
  - Nameservers (NS)
  - Mail exchange records (MX)
- IP resolution and ASN enrichment
- Ownership inference using keyword-based heuristics
- Structured output:
  - Console summary
  - JSON report
  - CSV report

---

## Use Cases
- SPF record analysis and validation  
- Third-party domain identification  
- Vulnerability management investigations  
- SecurityScorecard / external scan analysis  
- Domain infrastructure intelligence  

---

## Tech Stack
- Python
- python-whois
- dnspython
- requests (ipinfo API)

---

## Installation
```bash
pip install -r requirements.txt
