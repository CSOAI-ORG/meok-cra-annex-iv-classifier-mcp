# meok-cra-annex-iv-classifier-mcp

**EU Cyber Resilience Act product classifier — Annex III + Annex IV designations + Annex I requirements audit + signed certificates.**

Classifies products with digital elements (PDEs) into the CRA hierarchy. Built for the 11 Dec 2027 full-applicability deadline (vulnerability + serious-incident reporting already in force from Sept 2026).

By [MEOK AI Labs](https://meok.ai).

## Why this MCP

Implementing Regulation (EU) 2025/2392 (adopted late November 2025) just designated the first set of Class I, Class II, and Annex IV product categories. IoT vendors, chipmakers, smart-meter manufacturers, OT teams need a defensible classification NOW — every classification you delay is conformity work you'll pay for retroactively.

## What it classifies

- **Default class** — most consumer / business software (self-assessment, fines max €5M / 1%)
- **Important Class I** (Annex III(1)) — IAM, password managers, browsers, VPNs, OS, routers, smart home — self-assessment OR Notified Body (€10M / 2%)
- **Important Class II** (Annex III(2)) — hypervisors, firewalls, IDS/IPS, tamper-resistant µCs/µPs — MANDATORY Notified Body assessment (€15M / 2.5%)
- **Critical (Annex IV)** — smart-card secure elements, smart-meter gateways, hardware security boxes — mandatory European cybersecurity certification (€15M / 2.5%)

## Tools

- `classify_product` — heuristic classification by description + characteristics
- `audit_essential_requirements` — score against 15 Annex I cybersecurity requirements
- `generate_doc_template` — Annex VIII technical documentation skeleton
- `sign_classification_cert` — Pro: HMAC-SHA256 signed classification cert with public verify URL

## Install

```bash
pip install meok-cra-annex-iv-classifier-mcp
```

## Tiers

- **Free** — 10 classifications/day
- **Pro £199/mo** — unlimited + signed certs + monthly Annex III/IV update alerts — [subscribe](https://buy.stripe.com/14A4gB3K4eUWgYR56o8k836)
- **Enterprise £1,499/mo** — multi-product + custom designation rules
- **£199 per-product cert** — one-off signed classification

Use code **`MEOKEAT`** for 25% off the first 3 months.

## Sources

- Regulation (EU) 2024/2847 (CRA)
- Implementing Regulation (EU) 2025/2392 (first Annex III/IV designations)
- ENISA CRA implementation guidance

## Related MEOK MCPs

- [`cra-compliance-mcp`](https://pypi.org/project/cra-compliance-mcp/) — full CRA compliance audit
- [`ai-bom-mcp`](https://pypi.org/project/ai-bom-mcp/) — SBOM generation for Annex VIII
- [`meok-attestation-verify`](https://pypi.org/project/meok-attestation-verify/) — verify signed certs

## License

MIT — MEOK AI Labs, 2026.

---

## Distribution channels

- **PyPI**: `pip install meok-cra-annex-iv-classifier-mcp` (this package)
- **Apify Store** (Pay-Per-Event): https://apify.com/knowing_yucca/meok-cra-classifier
- **GitHub** (source): https://github.com/CSOAI-ORG/MEOK-LABS/tree/main/mcps/meok-cra-annex-iv-classifier-mcp
- **Sponsor**: https://github.com/sponsors/CSOAI-ORG · [Pro £79/mo →](https://buy.stripe.com/eVq9AV4O87sudMF42k8k839)

