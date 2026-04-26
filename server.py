#!/usr/bin/env python3
"""
EU CRA Annex IV Product Classifier MCP Server
================================================
By MEOK AI Labs | https://meok.ai

Classifies "products with digital elements" (PDEs) against the EU Cyber
Resilience Act (Regulation (EU) 2024/2847) class hierarchy + Annex IV
designations, and emits HMAC-signed classification certs.

CONTEXT (April 2026):
  Implementing Regulation (EU) 2025/2392 was adopted late November 2025 with
  the first set of Annex III + Annex IV designations. CRA full applicability
  begins 11 December 2027 but classification work is happening NOW. IoT vendors,
  chipmakers, smart-meter manufacturers, OT product teams need a defensible
  classification or they pay for it later in retroactive conformity work.

PROBLEM SOLVED: the CRA class hierarchy (default vs important Class I vs
important Class II vs critical Annex IV) is technical + lookup-heavy. No
queryable MCP exists yet. Reference architecture for the regulation.

  💷 PRICE: Free 10/day. Pro £199/mo unlimited + signed certs.
            Enterprise £1,499/mo + custom designation rules.
            £199 one-off per-product cert.

Install: pip install meok-cra-annex-iv-classifier-mcp
Run:     python server.py
"""

import json
import re
from datetime import datetime, timezone
from typing import Optional
from collections import defaultdict
from mcp.server.fastmcp import FastMCP

import os as _os
import sys
import os

_MEOK_API_KEY = _os.environ.get("MEOK_API_KEY", "")

try:
    sys.path.insert(0, os.path.expanduser("~/clawd/meok-labs-engine/shared"))
    from auth_middleware import check_access as _shared_check_access
except ImportError:
    def _shared_check_access(api_key: str = ""):
        if _MEOK_API_KEY and api_key and api_key == _MEOK_API_KEY:
            return True, "OK", "pro"
        if _MEOK_API_KEY and api_key and api_key != _MEOK_API_KEY:
            return False, "Invalid API key.", "free"
        return True, "OK", "free"


try:
    from attestation import get_attestation_tool_response
    _ATTESTATION_LOCAL = True
except ImportError:
    _ATTESTATION_LOCAL = False

# V-06 FIX: SSRF allowlist on attestation API URL.
try:
    from ssrf_safe import resolve_attestation_api as _resolve_api  # type: ignore
    _ATTESTATION_API = _resolve_api()
except ImportError:
    _ATTESTATION_API_RAW = _os.environ.get("MEOK_ATTESTATION_API", "https://meok-attestation-api.vercel.app")
    _ALLOWED_API_HOSTS = {"meok-attestation-api.vercel.app", "meok-verify.vercel.app", "meok.ai", "csoai.org", "councilof.ai", "compliance.meok.ai"}
    import urllib.parse as _urllib_parse
    try:
        _api_parsed = _urllib_parse.urlparse(_ATTESTATION_API_RAW)
        _api_host = (_api_parsed.hostname or "").lower()
        _api_scheme = (_api_parsed.scheme or "").lower()
    except Exception:
        _api_host, _api_scheme = "", ""
    if _api_scheme != "https" or _api_host not in _ALLOWED_API_HOSTS:
        _ATTESTATION_API = "https://meok-attestation-api.vercel.app"
    else:
        _ATTESTATION_API = _ATTESTATION_API_RAW.rstrip("/")


def check_access(api_key: str = ""):
    return _shared_check_access(api_key)


STRIPE_199 = "https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836"
STRIPE_1499 = "https://buy.stripe.com/4gM9AV80kaEG0ZT42k8k837"
FREE_DAILY_LIMIT = 10


# ── CRA classes per Annex III + IV (Regulation (EU) 2024/2847) ──
CRA_CLASSES = {
    "default": {
        "name": "Default class (no Annex III designation)",
        "examples": "Most consumer / business software, mobile apps, SaaS without critical-function role",
        "conformity_path": "Self-assessment (Module A — internal production control)",
        "documentation_required": "Annex VIII technical docs + EU declaration of conformity",
        "fines_max_eur": 5_000_000,
        "fines_max_pct_global_turnover": 1.0,
    },
    "class_i": {
        "name": "Important Class I (Annex III(1))",
        "designated_categories": [
            "Identity management systems + privileged access management software",
            "Standalone + embedded browsers",
            "Password managers",
            "Software searching for, removing or quarantining malicious software",
            "Products with digital elements with the function of VPN",
            "Network management systems",
            "SIEM systems",
            "Boot managers",
            "PKI + digital certificate issuance software",
            "Physical + virtual network interfaces",
            "Operating systems not covered by Class II",
            "Routers, modems intended for connection to the internet, switches not in Class II",
            "Microprocessors with security-related functionalities",
            "Microcontrollers with security-related functionalities",
            "ASICs and FPGAs intended for security-related use",
            "Smart home general purpose virtual assistants",
            "Smart home products with security functionalities including smart door locks, security cameras, baby monitoring systems and alarm systems",
            "Internet connected toys covered by Toy Safety Directive that have social interactive features or location tracking",
            "Personal wearables with security or health-monitoring functions",
        ],
        "conformity_path": "Self-assessment (Module A) OR EU type examination (Module B + C) OR full QMS (Module H)",
        "documentation_required": "Same as default + cybersecurity-by-design evidence",
        "fines_max_eur": 10_000_000,
        "fines_max_pct_global_turnover": 2.0,
    },
    "class_ii": {
        "name": "Important Class II (Annex III(2))",
        "designated_categories": [
            "Hypervisors and container runtimes systems supporting virtualised execution of operating systems and similar environments",
            "Firewalls, intrusion detection + prevention systems",
            "Tamper-resistant microprocessors",
            "Tamper-resistant microcontrollers",
        ],
        "conformity_path": "MANDATORY third-party conformity assessment by Notified Body (Module B+C OR Module H)",
        "documentation_required": "Same as Class I + Notified Body technical assessment",
        "fines_max_eur": 15_000_000,
        "fines_max_pct_global_turnover": 2.5,
    },
    "annex_iv_critical": {
        "name": "Critical (Annex IV)",
        "designated_categories": [
            "Hardware Devices with Security Boxes (per Implementing Regulation 2025/2392)",
            "Smart meter gateways within smart metering systems as defined in Article 2(7) of Directive (EU) 2019/944, and other devices for advanced security purposes, including for secure cryptoprocessing",
            "Smartcards or similar devices, including secure elements",
        ],
        "conformity_path": "Mandatory European cybersecurity certification scheme (EUCC) at substantial assurance level OR equivalent",
        "documentation_required": "Class II + EUCC certification per Reg (EU) 2019/881",
        "fines_max_eur": 15_000_000,
        "fines_max_pct_global_turnover": 2.5,
    },
}


# ── 13 Essential Cybersecurity Requirements (Annex I Part I) ────
ANNEX_I_REQUIREMENTS = {
    "1.1": "Delivered without known exploitable vulnerabilities",
    "1.2": "Delivered with secure-by-default configuration",
    "1.3": "Receive security updates including automatic updates",
    "1.4": "Protect against unauthorised access via authentication, identity management, access control",
    "1.5": "Protect confidentiality (encryption in transit + at rest)",
    "1.6": "Protect integrity — no unauthorised manipulation",
    "1.7": "Minimise attack surface — least privilege, no unnecessary interfaces",
    "1.8": "Reduce impact of incidents — mitigation mechanisms",
    "1.9": "Provide security-related information via logging + monitoring",
    "1.10": "Allow users to securely remove all data",
    "2.1": "Identify + document vulnerabilities + components (including SBOM)",
    "2.2": "Address vulnerabilities without delay — provide security updates",
    "2.3": "Apply effective + regular tests / reviews of security",
    "2.4": "Once a security update is available, share info about fixed vulnerabilities publicly",
    "2.5": "Enforce coordinated vulnerability disclosure policy",
}


# Classification heuristics — keyword → suggested class
CLASS_HEURISTICS = [
    (r"\b(smart\s?card|smartcard|secure\s?element|secure\s?cryptoprocess)\b", "annex_iv_critical"),
    (r"\b(smart\s?meter\s?gateway|HSM|hardware\s?security\s?module)\b", "annex_iv_critical"),
    (r"\b(hypervisor|container\s?runtime|firewall|intrusion\s?(detection|prevention))\b", "class_ii"),
    (r"\b(tamper[-\s]?resistant\s?microcontroller|tamper[-\s]?resistant\s?microprocessor)\b", "class_ii"),
    (r"\b(SIEM|password\s?manager|VPN|anti[-\s]?virus|antivirus|anti[-\s]?malware|PKI|certificate\s?authority|boot\s?manager|router|modem|switch)\b", "class_i"),
    (r"\b(smart\s?(door\s?lock|home|toy|wearable)|baby\s?monitor|security\s?camera|alarm\s?system)\b", "class_i"),
    (r"\b(virtual\s?assistant|voice\s?assistant)\b", "class_i"),
    (r"\b(operating\s?system|OS\b)\b", "class_i"),
    (r"\b(microcontroller|microprocessor|ASIC|FPGA)\b", "class_i"),
    (r"\b(identity\s?management|privileged\s?access|IAM|PAM)\b", "class_i"),
    (r"\b(browser)\b", "class_i"),
]


mcp = FastMCP(
    "meok-cra-annex-iv-classifier",
    instructions=(
        "MEOK AI Labs CRA Annex IV Classifier MCP. Classify products with digital "
        "elements (PDEs) against the EU Cyber Resilience Act (Regulation (EU) 2024/2847) "
        "class hierarchy: default / Class I / Class II / Annex IV critical. Audit against "
        "the 13 Essential Cybersecurity Requirements (Annex I). Emit HMAC-signed "
        "classification certificates ready for Notified Body submission. Built for the "
        "11 Dec 2027 enforcement window — but classifications need to start NOW."
    ),
)


@mcp.tool()
def classify_product(
    product_name: str,
    product_description: str,
    has_remote_data_processing: bool = False,
    intended_for_consumer_use: bool = False,
    intended_for_critical_infrastructure: bool = False,
    api_key: str = "",
) -> str:
    """Classify a product with digital elements (PDE) into the CRA class hierarchy.

    Returns: suggested class, conformity path, fines exposure, next steps.
    """
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})

    text = (product_name + " " + product_description).lower()
    matched_class = "default"
    matched_keywords = []
    for pattern, klass in CLASS_HEURISTICS:
        if re.search(pattern, text, re.IGNORECASE):
            # Take the most-restrictive class that matches
            current_rank = list(CRA_CLASSES.keys()).index(matched_class)
            new_rank = list(CRA_CLASSES.keys()).index(klass)
            if new_rank > current_rank:
                matched_class = klass
            matched_keywords.append((klass, pattern))

    cls = CRA_CLASSES[matched_class]
    return json.dumps({
        "product_name": product_name,
        "suggested_class_key": matched_class,
        "suggested_class_name": cls["name"],
        "matched_keywords": [{"class": c, "pattern": p} for c, p in matched_keywords],
        "conformity_path": cls["conformity_path"],
        "documentation_required": cls["documentation_required"],
        "fines_max_eur": cls["fines_max_eur"],
        "fines_max_pct_global_turnover": cls["fines_max_pct_global_turnover"],
        "intended_for_consumer_use": intended_for_consumer_use,
        "intended_for_critical_infrastructure": intended_for_critical_infrastructure,
        "regulatory_basis": "Regulation (EU) 2024/2847 + Implementing Regulation (EU) 2025/2392",
        "enforcement_full_applicability": "2027-12-11",
        "obligations_already_in_force": "Vulnerability + serious-incident reporting from 2026-09-11",
        "next_step": "Call audit_essential_requirements() to verify Annex I compliance",
        "uncertainty_warning": "Heuristic-based classification — for binding determination engage Notified Body OR upgrade to Pro for signed pre-classification cert auditors accept",
        "upsell": f"Pro £199/mo: signed classification certs + monthly Annex III/IV update alerts: {STRIPE_199}" if tier == "free" else None,
    }, indent=2)


@mcp.tool()
def audit_essential_requirements(
    product_name: str,
    requirements_satisfied_csv: str,
    api_key: str = "",
) -> str:
    """Audit a product against the 15 Annex I + II essential requirements.
    Pass comma-separated requirement IDs that are satisfied (e.g. "1.1,1.2,2.1")."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})

    satisfied = set(r.strip() for r in requirements_satisfied_csv.split(",") if r.strip())
    all_reqs = set(ANNEX_I_REQUIREMENTS.keys())
    missing = sorted(all_reqs - satisfied)
    score = round(100 * len(satisfied & all_reqs) / len(all_reqs), 1)

    return json.dumps({
        "product_name": product_name,
        "score_percent": score,
        "satisfied": sorted(satisfied & all_reqs),
        "missing": missing,
        "missing_descriptions": {k: ANNEX_I_REQUIREMENTS[k] for k in missing},
        "verdict": (
            "READY for self-assessment / Notified Body submission" if score >= 95 else
            "NEAR-READY — close the missing requirements then re-audit" if score >= 75 else
            "NOT READY — material gaps remain"
        ),
        "all_15_requirements": ANNEX_I_REQUIREMENTS,
        "upsell": f"Pro £199/mo: signed audit cert + remediation roadmap: {STRIPE_199}" if tier == "free" else None,
    }, indent=2)


@mcp.tool()
def generate_doc_template(class_key: str = "default", api_key: str = "") -> str:
    """Generate the Annex VIII technical documentation skeleton for a given class."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if class_key not in CRA_CLASSES:
        return json.dumps({"error": f"unknown class_key: {class_key}", "valid": list(CRA_CLASSES.keys())})

    cls = CRA_CLASSES[class_key]
    template = {
        "_meta": {
            "title": "EU CRA Annex VIII Technical Documentation",
            "regulation": "Regulation (EU) 2024/2847",
            "product_class": cls["name"],
            "conformity_path": cls["conformity_path"],
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "generator": "meok-cra-annex-iv-classifier-mcp v1.0",
        },
        "1_general_description": {
            "product_identifier": "",
            "intended_purpose": "",
            "intended_user_groups": "",
            "operating_environment": "",
            "geographic_scope": "",
        },
        "2_design_and_development": {
            "architecture_diagram_attached": False,
            "data_flow_diagram_attached": False,
            "components_description": [],
            "third_party_components": [],
            "open_source_components_with_sbom": "Attach CycloneDX or SPDX SBOM",
        },
        "3_essential_cybersecurity_requirements_evidence": {
            req_id: {"requirement": ANNEX_I_REQUIREMENTS[req_id], "evidence_attached": False}
            for req_id in ANNEX_I_REQUIREMENTS
        },
        "4_vulnerability_handling": {
            "policy_published_url": "",
            "coordinated_vulnerability_disclosure_contact": "",
            "security_update_mechanism_description": "",
            "support_period_years": "",
        },
        "5_risk_assessment": {
            "risk_register_attached": False,
            "residual_risks_accepted_by": "",
            "review_cadence_months": 6,
        },
        "6_testing_and_validation": {
            "internal_test_reports_attached": [],
            "third_party_pentest_attached": False,
            "automated_security_testing": "",
        },
        "7_eu_declaration_of_conformity": {
            "filed": False,
            "harmonised_standards_applied": [],
            "notified_body_id_if_applicable": "",
        },
        "8_post_market_obligations": {
            "vulnerability_reporting_to_csirt_24h_runbook": False,
            "serious_incident_reporting_72h_runbook": False,
            "user_information_mechanism": "",
        },
    }
    return json.dumps(template, indent=2)


@mcp.tool()
def sign_classification_cert(
    entity_name: str,
    product_name: str,
    classification_class_key: str,
    annex_i_score: float,
    findings_csv: str = "",
    api_key: str = "",
    email: str = "",
) -> str:
    """Generate a HMAC-SHA256 signed CRA classification certificate (Pro/Enterprise)."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return json.dumps({"error": msg, "upgrade_url": STRIPE_199})
    if tier == "free":
        return json.dumps({
            "error": "Signed CRA classification certs require Pro (£199/mo).",
            "upgrade_url": STRIPE_199,
        })
    if classification_class_key not in CRA_CLASSES:
        return json.dumps({"error": f"unknown class: {classification_class_key}"})

    cls = CRA_CLASSES[classification_class_key]
    findings = [f.strip() for f in findings_csv.split(",") if f.strip()] or [
        f"Product: {product_name}",
        f"Suggested class: {cls['name']}",
        f"Annex I requirements score: {annex_i_score}%",
        f"Conformity path: {cls['conformity_path']}",
    ]
    payload = {
        "regulation": "EU Cyber Resilience Act (Regulation (EU) 2024/2847) — Annex IV classification",
        "entity": f"{entity_name} — product: {product_name}",
        "score": annex_i_score,
        "findings": findings,
        "tier": tier,
    }
    if _ATTESTATION_LOCAL:
        cert = get_attestation_tool_response(
            regulation=payload["regulation"], entity=payload["entity"],
            score=annex_i_score, findings=findings,
            articles_audited=list(ANNEX_I_REQUIREMENTS.keys()),
            tier=tier,
        )
    else:
        import urllib.request as _url
        try:
            req = _url.Request(
                f"{_ATTESTATION_API}/sign",
                data=json.dumps({"api_key": api_key, "email": email, **payload}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with _url.urlopen(req, timeout=15) as resp:
                cert = json.loads(resp.read())
        except Exception as e:
            return json.dumps({"error": f"Attestation API unreachable: {e}"})
    return json.dumps(cert, indent=2)


def main():
    mcp.run()


if __name__ == "__main__":
    main()
