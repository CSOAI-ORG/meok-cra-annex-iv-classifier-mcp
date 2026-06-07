[![MCP Scorecard: 90/100](https://img.shields.io/badge/proofof.ai-90%2F100-5b21b6)](https://proofof.ai/scorecard/meok-cra-annex-iv-classifier-mcp.html)

# Meok Cra Annex Iv Classifier MCP

[![MEOK AI Labs](https://img.shields.io/badge/MEOK-AI%20Labs-667eea)](https://meok.ai)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-22c55e)](https://councilof.ai)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PyPI](https://img.shields.io/badge/PyPI-Install-3775a9)](https://pypi.org/project/meok_cra_annex_iv_classifier_mcp/)
[![PyPI](https://img.shields.io/pypi/v/meok-cra-annex-iv-classifier-mcp)](https://pypi.org/project/meok-cra-annex-iv-classifier-mcp/) [![Python](https://img.shields.io/pypi/pyversions/meok-cra-annex-iv-classifier-mcp)](https://pypi.org/project/meok-cra-annex-iv-classifier-mcp/)


**EU Cyber Resilience Act product classifier — Annex III + Annex IV designations + Annex I requirements audit + signed certificates.**

> EU CRA (Cyber Resilience Act, Reg 2024/2847) Annex IV classifier — 9-category essential security ...

EU CRA (Cyber Resilience Act, Reg 2024/2847) Annex IV classifier — 9-category essential security requirements with HMAC-signed compliance attestations. By MEOK AI Labs.

---

## 🚀 Quick Start

```bash
# Install via pip
pip install meok_cra_annex_iv_classifier_mcp

# Or install via Smithery
npx -y @smithery/cli@latest install meok-cra-annex-iv-classifier-mcp --client claude
```

## ✨ Features

- MCP protocol compliant
- Easy installation
- Well-documented API
- Production-ready
- Active maintenance
- **Free** — 10 classifications/day
- **Pro £199/mo** — unlimited + signed certs + monthly Annex III/IV update alerts — [subscribe](https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j)
- **Enterprise £1,499/mo** — multi-product + custom designation rules
- **£199 per-product cert** — one-off signed classification

## 📖 Documentation

- [Full Documentation](https://docs.meok.ai/meok-cra-annex-iv-classifier-mcp)
- [API Reference](https://api.meok.ai)
- [EU AI Act Compliance Guide](https://councilof.ai/compliance)

## 🛡️ Compliance

This MCP server is built with **EU AI Act compliance** built-in:

- ✅ Article 9 — Risk Management System
- ✅ Article 13 — Transparency & Instructions for Use
- ✅ Article 15 — Bias Detection & Testing
- ✅ Article 26 — FRIA Support (where applicable)
- ✅ Article 50 — AI Content Watermarking (where applicable)

Need help getting compliant? **[Book a free 15-min diagnostic →](https://cal.com/csoai/august-audit)**

## 🏢 Enterprise

Need custom development, SLA guarantees, or white-label deployment?

- **Pro:** $99/mo — Full MCP suite + EU AI Act tracking
- **Enterprise:** $499/mo — Custom dev + SLA + Dedicated support

[View Pricing →](https://councilof.ai/pricing) | [Contact Sales →](mailto:sales@csoai.org)

## 🤝 Part of the MEOK Ecosystem

This server is part of the **[MEOK AI Labs](https://meok.ai)** ecosystem — 300+ MCP servers for sovereign AI governance.

| Domain | Purpose |
|--------|---------|
| [councilof.ai](https://councilof.ai) | EU AI Act compliance marketplace |
| [safetyof.ai](https://safetyof.ai) | AI safety & monitoring |
| [meok.ai](https://meok.ai) | Sovereign AI platform |
| [cobolbridge.ai](https://cobolbridge.ai) | Legacy modernization |

## 📜 License

MIT © [CSOAI-ORG](https://github.com/CSOAI-ORG)

---

<p align="center">
  <sub>Built with 💜 by <a href="https://meok.ai">MEOK AI Labs</a> · UK Companies House 16939677</sub>
</p>
<!-- mcp-name: io.github.CSOAI-ORG/meok-cra-annex-iv-classifier-mcp -->

<!-- meok-moat-footer-v1 -->
---

## Pairs with MEOK Governance Suite

Build something that touches users? You need compliance. MEOK ships 38 governance MCPs that drop in alongside this tool — EU AI Act, DORA, NIS2, CRA, GDPR, ISO 42001, FDA SaMD, MDR, Basel, MiFID II, MiCA, COPPA, and more.

```bash
# One-shot install of the governance pack
npx meok-setup --pack governance
```

Free tier: 10 calls/day per MCP. Pro tier (£79/mo): unlimited + cryptographically signed compliance attestations your auditor verifies independently.

→ Full catalogue: [councilof.ai/catalogue](https://councilof.ai/catalogue)
→ MEOK AI Labs: [meok.ai](https://meok.ai)

<!-- BUY-LADDER:START -->

## 💸 Try MEOK in 30 seconds — instant buy ladder

| Tier | Price | What you get | Stripe |
|---|---|---|---|
| Smoke test | **£1** | Signed sample MCP-Hardening report + Article 50 PDF | <https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j> |
| Quick Kit | **£9** | EU AI Act Article 50 implementation guide (C2PA + EU-Icon) | <https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j> |
| Founder Call | **£29** | 30-min 1-on-1 with the founder | <https://buy.stripe.com/5kQ6oJ0xS3ce8sl7ew8k91j> |

> Refundable. UK Stripe — VAT-clean. Builds on the 81-MCP MEOK fleet.
> Verify any signed report at <https://meok.ai/verify>.

<!-- BUY-LADDER:END -->



## Configuration

Add to your `claude_desktop_config.json` (Claude Desktop) or your MCP client config:

```json
{
  "mcpServers": {
    "meok-cra-annex-iv-classifier-mcp": {
      "command": "uvx",
      "args": ["meok-cra-annex-iv-classifier-mcp"]
    }
  }
}
```

Or: `pip install meok-cra-annex-iv-classifier-mcp` then run the `meok-cra-annex-iv-classifier-mcp` command (stdio transport).

## Examples

Once configured, ask your assistant, for example:
- "Use `classify_product` to …"
- "Use `audit_essential_requirements` to …"
- "Use `generate_doc_template` to …"
