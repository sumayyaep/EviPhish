"""Evidence Gap Analyzer for EviPhish.

Identifies missing pieces of forensic context necessary to reach definitive conclusions
without guessing. Explicitly marks items as Not Collected / Unavailable rather than
treating absence of information as guilt or innocence.
"""

from typing import Any


class EvidenceGapAnalyzer:
    """Analyzes forensic gaps and provides actionable collection recommendations."""

    def analyze_gaps(self, parsed_data: dict[str, Any], evidence_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify missing evidence items and describe their analytical value."""
        gaps: list[dict[str, Any]] = []
        auth = parsed_data.get("auth_results", {})
        urls = parsed_data.get("urls", [])
        attachments = parsed_data.get("attachments", [])

        # Gap 1: Independent DNS & Authentication Verification
        spf_missing = auth.get("spf", {}).get("status") == "UNKNOWN"
        dkim_missing = auth.get("dkim", {}).get("status") == "UNKNOWN"
        dmarc_missing = auth.get("dmarc", {}).get("status") == "UNKNOWN"

        if spf_missing or dkim_missing or dmarc_missing:
            gaps.append({
                "gap_id": "GAP-AUTH-DNS",
                "category": "Authentication & DNS Verification",
                "title": "Independent DNS & Domain Policy Records",
                "status": "NOT_COLLECTED",
                "why_needed": (
                    "The email headers lack one or more authentication status fields (SPF, DKIM, or DMARC). "
                    "Querying current DNS TXT records for SPF (_spf/root TXT) and DMARC (_dmarc.<domain>) "
                    "would confirm if the sending domain actually published defensive email security policies."
                ),
                "collection_source": "Authoritative DNS Records (TXT, MX)",
                "impact_on_conclusion": "Confirms whether the sender identity was spoofed or authorized."
            })

        # Gap 2: URL Redirection & Live Landing Page Analysis
        if urls:
            gaps.append({
                "gap_id": "GAP-URL-REDIRECT",
                "category": "Network & Web Telemetry",
                "title": "URL Redirection Chain & Final Landing Page Status",
                "status": "NOT_COLLECTED",
                "why_needed": (
                    f"Extracted {len(urls)} link(s) without following redirects. Phishing campaigns frequently chain "
                    "multiple open redirects or URL shorteners to mask final credential-harvesting landing pages."
                ),
                "collection_source": "Isolated Sandbox / Headless Browser Web Crawler",
                "impact_on_conclusion": (
                    "Determines if the link serves a login form, credential harvesting kit, or benign content."
                )
            })

        # Gap 3: Domain Age and WHOIS Context
        if parsed_data.get("domains"):
            gaps.append({
                "gap_id": "GAP-DOMAIN-WHOIS",
                "category": "Threat Intelligence Context",
                "title": "Domain Registration Age & WHOIS History",
                "status": "NOT_COLLECTED",
                "why_needed": (
                    "Newly Registered Domains (NRDs < 30 days old) have high correlation with active phishing campaigns. "
                    "Checking creation dates distinguishes long-standing enterprise infrastructure from ephemeral threat sites."
                ),
                "collection_source": "RDAP / WHOIS Registrars & Passive DNS",
                "impact_on_conclusion": "Provides threat context without evaluating subjective email text."
            })

        # Gap 4: Mail Gateway & Server SMTP Logs
        gaps.append({
            "gap_id": "GAP-MTA-LOGS",
            "category": "Infrastructure Logs",
            "title": "Mail Server (MTA/MX) SMTP Transaction Logs",
            "status": "NOT_COLLECTED",
            "why_needed": (
                "Header fields (such as intermediate Received lines) can be forged by previous relays. Correlating "
                "the external connecting IP address and TLS handshake in MTA logs verifies the authentic ingress connection."
            ),
            "collection_source": "Perimeter Mail Transfer Agent (Postfix/Exchange/Google Workspace) Logs",
            "impact_on_conclusion": "Verifies true origin IP address and transport encryption parameters."
        })

        # Gap 5: Endpoint & Web Proxy Telemetry (User Action Corroboration)
        gaps.append({
            "gap_id": "GAP-USER-TELEMETRY",
            "category": "Endpoint & Proxy Telemetry",
            "title": "User Interaction & Browser Click Telemetry",
            "status": "NOT_COLLECTED",
            "why_needed": (
                "Static email files only show what was received, not what happened after delivery. Web proxy logs, "
                "DNS queries from the recipient's endpoint, and EDR process trees are required to determine whether "
                "links were clicked or malicious payloads executed."
            ),
            "collection_source": "EDR (CrowdStrike/Defender) & Secure Web Gateway (Zscaler/Palo Alto) Logs",
            "impact_on_conclusion": "Distinguishes a benign delivery attempt from a successful security compromise."
        })

        # Gap 6: Attachment Sandbox Detonation
        if attachments:
            gaps.append({
                "gap_id": "GAP-ATTACHMENT-SANDBOX",
                "category": "Malware Analysis",
                "title": "Dynamic Sandbox Detonation Telemetry",
                "status": "NOT_COLLECTED",
                "why_needed": (
                    f"Found {len(attachments)} file attachment(s). Static MIME analysis extracted hashes but cannot "
                    "detect macro execution, DLL sideloading, or exploits without dynamic sandbox analysis."
                ),
                "collection_source": "Automated Malware Sandbox (Cuckoo/Any.Run/Joe Sandbox)",
                "impact_on_conclusion": "Establishes whether attachments possess weaponized exploit payloads."
            })

        return gaps
