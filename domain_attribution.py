"""
SPF Domain Ownership Investigation Script
==========================================
Performs WHOIS, NS lookup, and ASN lookup for all domains in the
SecurityScorecard malformed SPF findings and outputs an ownership summary.

Requirements:
    pip install python-whois dnspython requests
"""

import whois
import dns.resolver
import requests
import json
import time
import socket
from datetime import datetime

# ── Domains from the SecurityScorecard findings ──────────────────────────────

DOMAINS = [
    "subscriptionsave.co.uk",
    "familynotices24.co.uk",
    "newsquestscotlandevents.com",
    "creativelife.agency",
    "cngroup.co.uk",
    "timesout.co.uk",
    "forthweeklypress.co.uk",
    "insurancetimes.co.uk",
    "newsquestspecialistmedia.co.uk",
    "cumbrian-newspapers.co.uk",
    "northnorfolknews.co.uk",
    "thestradshop.com",
    "dandglife.co.uk",
    "scotlandshomes.co.uk",
    "globalreinsurance.com",
    "indeonline.com",
    "shelbystar.com",
]

# Keywords to detect Gannett-family ownership
GANNETT_KEYWORDS = [
    "gannett", "newsquest", "usa today", "usatoday",
    "herald & times", "heraldandtimes", "cngroup",
    "local world", "newquest"
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def is_gannett(text: str) -> bool:
    """Return True if any Gannett-family keyword appears in the text."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in GANNETT_KEYWORDS)


def whois_lookup(domain: str) -> dict:
    """Return key WHOIS fields for a domain."""
    result = {
        "registrant_org": "N/A",
        "registrant_email": "N/A",
        "registrar": "N/A",
        "creation_date": "N/A",
        "raw_snippet": "",
    }
    try:
        w = whois.whois(domain)
        result["registrant_org"]   = str(w.org   or w.registrant or "N/A").strip()
        result["registrant_email"] = str(w.emails[0] if isinstance(w.emails, list) and w.emails
                                         else (w.emails or "N/A")).strip()
        result["registrar"]        = str(w.registrar or "N/A").strip()
        if w.creation_date:
            cd = w.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            result["creation_date"] = cd.strftime("%Y-%m-%d") if hasattr(cd, "strftime") else str(cd)
        # Capture a raw snippet for manual review
        raw = w.text or ""
        result["raw_snippet"] = raw[:600].replace("\n", " | ")
    except Exception as e:
        result["error"] = str(e)
    return result


def ns_lookup(domain: str) -> list:
    """Return a list of nameserver hostnames for the domain."""
    try:
        answers = dns.resolver.resolve(domain, "NS")
        return sorted(str(r.target).rstrip(".").lower() for r in answers)
    except Exception as e:
        return [f"ERROR: {e}"]


def mx_lookup(domain: str) -> list:
    """Return a list of MX hostnames for the domain."""
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return sorted(str(r.exchange).rstrip(".").lower() for r in answers)
    except Exception:
        return []


def resolve_ip(domain: str) -> str:
    """Resolve the domain's A record to an IP."""
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return "N/A"


def asn_lookup(ip: str) -> dict:
    """Query ipinfo.io for ASN / org details of an IP address."""
    result = {"asn": "N/A", "org": "N/A", "country": "N/A"}
    if ip in ("N/A", ""):
        return result
    try:
        r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        if r.status_code == 200:
            data = r.json()
            result["asn"]     = data.get("org", "N/A").split()[0]   # e.g. AS15169
            result["org"]     = " ".join(data.get("org", "N/A").split()[1:])  # e.g. Google LLC
            result["country"] = data.get("country", "N/A")
    except Exception as e:
        result["error"] = str(e)
    return result


def infer_owner(domain, whois_data, nameservers, asn_data) -> str:
    """Heuristic: determine if domain likely belongs to Gannett family."""
    combined = " ".join([
        whois_data.get("registrant_org", ""),
        whois_data.get("registrant_email", ""),
        whois_data.get("registrar", ""),
        whois_data.get("raw_snippet", ""),
        " ".join(nameservers),
        asn_data.get("org", ""),
        domain,
    ])
    if is_gannett(combined):
        return "✅ Gannett / Newsquest"
    return "❓ Unknown / Third-party"


# ── Main ──────────────────────────────────────────────────────────────────────

def investigate(domains: list) -> list:
    results = []
    for i, domain in enumerate(domains, 1):
        print(f"[{i:02d}/{len(domains)}] Investigating: {domain}")

        whois_data  = whois_lookup(domain)
        nameservers = ns_lookup(domain)
        mx_records  = mx_lookup(domain)
        ip          = resolve_ip(domain)
        asn_data    = asn_lookup(ip)
        owner       = infer_owner(domain, whois_data, nameservers, asn_data)

        results.append({
            "domain":           domain,
            "inferred_owner":   owner,
            "ip":               ip,
            "registrant_org":   whois_data["registrant_org"],
            "registrant_email": whois_data["registrant_email"],
            "registrar":        whois_data["registrar"],
            "creation_date":    whois_data["creation_date"],
            "nameservers":      nameservers,
            "mx_records":       mx_records,
            "asn":              asn_data["asn"],
            "asn_org":          asn_data["org"],
            "asn_country":      asn_data["country"],
            "whois_snippet":    whois_data.get("raw_snippet", ""),
            "whois_error":      whois_data.get("error", ""),
        })

        time.sleep(1.2)  # polite delay between requests

    return results


def print_summary(results: list):
    sep  = "-" * 120
    wide = "{:<35} {:<28} {:<18} {:<20} {:<15}"
    print("\n" + "=" * 120)
    print("  DOMAIN OWNERSHIP INVESTIGATION SUMMARY")
    print("  Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("=" * 120)
    print(wide.format("Domain", "Inferred Owner", "IP", "Registrant Org", "ASN"))
    print(sep)
    for r in results:
        print(wide.format(
            r["domain"][:34],
            r["inferred_owner"][:27],
            r["ip"][:17],
            r["registrant_org"][:19],
            r["asn"][:14],
        ))
    print(sep)

    # Breakdown
    gannett   = [r for r in results if "Gannett" in r["inferred_owner"]]
    unknown   = [r for r in results if "Unknown" in r["inferred_owner"]]
    print(f"\n  ✅ Gannett / Newsquest confirmed : {len(gannett)}")
    print(f"  ❓ Unknown / needs manual review : {len(unknown)}")

    if unknown:
        print("\n  Domains needing manual review:")
        for r in unknown:
            print(f"    • {r['domain']}  |  NS: {', '.join(r['nameservers'][:2])}")

    print("\n  Nameserver breakdown:")
    from collections import Counter
    all_ns = [ns for r in results for ns in r["nameservers"]]
    for ns, count in Counter(all_ns).most_common(10):
        print(f"    {count:2d}x  {ns}")

    print("\n  ASN breakdown:")
    all_asn = [f"{r['asn']} ({r['asn_org']})" for r in results if r["asn"] != "N/A"]
    for asn, count in Counter(all_asn).most_common(8):
        print(f"    {count:2d}x  {asn}")


def save_json(results: list, path: str = "spf_investigation_results.json"):
    with open(path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Full results saved to: {path}")


def save_csv(results: list, path: str = "spf_investigation_results.csv"):
    import csv
    fields = [
        "domain", "inferred_owner", "ip", "registrant_org",
        "registrant_email", "registrar", "creation_date",
        "nameservers", "mx_records", "asn", "asn_org", "asn_country",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            row = dict(r)
            row["nameservers"] = "; ".join(r["nameservers"])
            row["mx_records"]  = "; ".join(r["mx_records"])
            writer.writerow(row)
    print(f"  CSV saved to: {path}")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Starting domain ownership investigation...")
    print(f"Domains to check: {len(DOMAINS)}\n")

    results = investigate(DOMAINS)

    print_summary(results)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    save_json(results, "spf_investigation_results.json")
    save_csv(results, f"spf_investigation_results_{timestamp}.csv")

    print("\nDone.")
