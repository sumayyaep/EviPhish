import re
import urllib.parse
from typing import Any
from backend.app.parser.eml_parser import ForensicEmailData

class PhishingDetector:
    """Deterministic, explainable rule-based phishing detection engine."""

    URGENCY_PATTERNS = [
        re.compile(r'\b(urgent|immediately|immediate action|within 24 hours|action required|final notice)\b', re.IGNORECASE),
        re.compile(r'\b(account (is|will be) (suspended|terminated|disabled|locked|closed|deactivated))\b', re.IGNORECASE),
        re.compile(r'\b(unauthorized (access|activity|charges|transaction)|suspicious (login|activity))\b', re.IGNORECASE),
    ]

    CREDENTIAL_PATTERNS = [
        re.compile(r'\b(verify (your )?(account|identity|password|credentials|profile))\b', re.IGNORECASE),
        re.compile(r'\b(update (your )?(billing|payment|security|password|login))\b', re.IGNORECASE),
        re.compile(r'\b(confirm (your )?(identity|details|credentials|email))\b', re.IGNORECASE),
        re.compile(r'\b(click here to (log in|login|verify|unlock|reactivate))\b', re.IGNORECASE),
    ]

    DANGEROUS_EXTENSIONS = {
        '.exe', '.scr', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.ps1',
        '.iso', '.img', '.hta'
    }
    
    HTML_EXTENSIONS = {'.htm', '.html'}

    def detect(self, parsed_email: ForensicEmailData, evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
        """Automatically analyze parsed email data and determine phishing verdict."""
        score = 0
        key_indicators: list[dict[str, Any]] = []
        mitigating_factors: list[str] = []
        limitations: list[str] = [
            "Analysis is purely static based on supplied RFC 5322 headers and body artifacts.",
            "No active DNS queries or outbound HTTP requests were initiated to maintain analyst OPSEC.",
            "Static analysis cannot prove recipient interaction or victim compromise without endpoint logs."
        ]

        def find_evidence_ids(type_substring: str) -> list[str]:
            return [e["id"] for e in evidence_items if type_substring.upper() in e.get("evidence_type", "").upper()]

        # 1. Deceptive Link Text vs Destination Mismatches
        anchor_mismatches = [d for d in parsed_email.discrepancies if d.get("type") == "ANCHOR_TEXT_DESTINATION_MISMATCH"]
        if anchor_mismatches:
            score += 45
            ev_ids = find_evidence_ids("URL_TEXT_MISMATCH")
            for m in anchor_mismatches:
                key_indicators.append({
                    "id": "IND-LINK-MISMATCH",
                    "name": "Deceptive Hyperlink Destination Discrepancy",
                    "severity": "CRITICAL",
                    "description": (
                        f"Anchor text displays '{m.get('apparent_domain')}', but actual destination targets "
                        f"'{m.get('target_domain')}'. This is a hallmark deception tactic."
                    ),
                    "evidence_ids": ev_ids
                })

        # 2. Authentication Failures vs Successes (Gathering facts, applying penalty if failed)
        auth = parsed_email.auth_results
        spf_status = auth.get("spf", {}).get("status", "UNKNOWN").upper()
        dkim_status = auth.get("dkim", {}).get("status", "UNKNOWN").upper()
        dmarc_status = auth.get("dmarc", {}).get("status", "UNKNOWN").upper()

        auth_failed = False
        failed_mechanisms = []
        
        if dmarc_status == "FAIL":
            auth_failed = True
            failed_mechanisms.append("DMARC")
        elif dmarc_status == "UNKNOWN":
            if spf_status == "FAIL" and dkim_status == "FAIL":
                auth_failed = True
                failed_mechanisms.extend(["SPF", "DKIM"])

        if auth_failed:
            score += 30
            ev_ids = find_evidence_ids("AUTH")
            key_indicators.append({
                "id": "IND-AUTH-FAIL",
                "name": "Perimeter Email Authentication Failure",
                "severity": "HIGH",
                "description": f"Receiving gateway headers explicitly record failed verification for: {', '.join(failed_mechanisms)}. (DMARC failure or both SPF/DKIM failure).",
                "evidence_ids": ev_ids
            })
            
        if spf_status == "UNKNOWN" and dkim_status == "UNKNOWN" and dmarc_status == "UNKNOWN":
            limitations.append("Email lacks all perimeter authentication headers (SPF, DKIM, DMARC are UNKNOWN).")

        # 3. Sender & Envelope Routing Discrepancies
        reply_mismatches = [d for d in parsed_email.discrepancies if d.get("type") == "FROM_REPLYTO_DOMAIN_MISMATCH"]
        return_mismatches = [d for d in parsed_email.discrepancies if d.get("type") == "FROM_RETURNPATH_DOMAIN_MISMATCH"]
        
        if reply_mismatches:
            score += 15
            ev_ids = find_evidence_ids("DOMAIN_ALIGNMENT_MISMATCH")
            descriptions = [d.get("description", "") for d in reply_mismatches]
            key_indicators.append({
                "id": "IND-REPLYTO-MISMATCH",
                "name": "Reply-To Domain Discrepancy",
                "severity": "MEDIUM",
                "description": f"The Reply-To domain differs from the From domain, which can redirect user replies to an attacker. {'; '.join(descriptions)}",
                "evidence_ids": ev_ids
            })
            
        if return_mismatches:
            score += 5
            descriptions = [d.get("description", "") for d in return_mismatches]
            mitigating_factors.append(f"Return-Path mismatch detected ({'; '.join(descriptions)}). This is common for newsletters, automated alerts, and mailing lists.")

        # 4. Phishing Urgency & Credential Harvesting Language
        subject = parsed_email.headers.get("subject", "")
        body_text = (parsed_email.safe_body_text or parsed_email.body_plain or "")
        full_text = f"{subject}\n{body_text}"

        has_urgency = any(p.search(full_text) for p in self.URGENCY_PATTERNS)
        has_cred_lure = any(p.search(full_text) for p in self.CREDENTIAL_PATTERNS)

        if has_urgency or has_cred_lure:
            lure_points = 0
            reasons = []
            if has_urgency:
                lure_points += 10
                reasons.append("coercive urgency or account suspension warnings")
            if has_cred_lure:
                lure_points += 15
                reasons.append("credential verification / login prompts")
            
            score += min(lure_points, 25)
            ev_ids = find_evidence_ids("HEADER_SUBJECT")
            key_indicators.append({
                "id": "IND-SOCIAL-ENG",
                "name": "Social Engineering Language Detected",
                "severity": "MEDIUM",
                "description": f"Message content employs {' and '.join(reasons)}.",
                "evidence_ids": ev_ids
            })

        # 5. Suspicious URL Structures
        suspicious_urls = []
        for u in parsed_email.urls:
            raw_url = u.get("url", "")
            try:
                parsed = urllib.parse.urlparse(raw_url)
                host = parsed.netloc.split(":")[0].strip()

                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host):
                    suspicious_urls.append(f"Direct IP address hostname: {raw_url}")
                elif "@" in parsed.netloc:
                    suspicious_urls.append(f"Ambiguous userinfo authority in URL: {raw_url}")
            except Exception:
                continue

        if suspicious_urls:
            score += 20
            ev_ids = find_evidence_ids("BODY_URL")
            key_indicators.append({
                "id": "IND-URL-STRUCT",
                "name": "Suspicious URL Structure Detected",
                "severity": "MEDIUM",
                "description": "; ".join(suspicious_urls[:3]),
                "evidence_ids": ev_ids
            })

        # 6. Attachment Risk Metadata
        risky_attachments = []
        html_attachments = []
        for att in parsed_email.attachments:
            fname = att.get("filename", "").lower()
            if any(fname.endswith(ext) for ext in self.DANGEROUS_EXTENSIONS):
                risky_attachments.append(f"{att.get('filename')} ({att.get('content_type')})")
            elif any(fname.endswith(ext) for ext in self.HTML_EXTENSIONS):
                html_attachments.append(f"{att.get('filename')} ({att.get('content_type')})")

        if risky_attachments:
            score += 30
            ev_ids = find_evidence_ids("ATTACHMENT")
            key_indicators.append({
                "id": "IND-ATTACHMENT-RISK",
                "name": "Dangerous Attachment Type",
                "severity": "HIGH",
                "description": f"Contains executable or script payload attachment(s): {', '.join(risky_attachments)}.",
                "evidence_ids": ev_ids
            })
            
        if html_attachments:
            # Only heavily penalize HTML attachments if there's a credential lure.
            points = 15 if has_cred_lure else 5
            score += points
            ev_ids = find_evidence_ids("ATTACHMENT")
            key_indicators.append({
                "id": "IND-ATTACHMENT-HTML",
                "name": "HTML Attachment",
                "severity": "MEDIUM" if has_cred_lure else "LOW",
                "description": f"Contains HTML attachment(s): {', '.join(html_attachments)}. HTML attachments can be used for smuggling or local credential harvesting, but are also used legitimately.",
                "evidence_ids": ev_ids
            })

        # 7. Apply Authentication Mitigations Conditionally
        auth_passed = dmarc_status == "PASS" or (spf_status == "PASS" and dkim_status == "PASS")
        has_severe_content_risk = bool(risky_attachments) or (has_cred_lure and (html_attachments or anchor_mismatches or suspicious_urls))
        
        if auth_passed:
            if has_severe_content_risk:
                mitigating_factors.append("Authentication explicitly passed, but severe content indicators (like dangerous attachments or credential lures) supersede authentication. This may indicate a compromised sender account.")
            else:
                mitigating_factors.append("Authentication mechanisms (DMARC or SPF+DKIM) explicitly passed.")
                score -= 20
        elif spf_status == "FAIL" and (dkim_status == "PASS" or dmarc_status == "PASS"):
            mitigating_factors.append("SPF failed but DKIM or DMARC passed, likely indicating a forwarded message or mailing list, rather than spoofing.")

        # 8. Verdict & Plain-Language Explanation Synthesis
        normalized_score = max(0, min(100, score))

        if normalized_score >= 50 or (anchor_mismatches and (auth_failed or has_cred_lure)):
            verdict = "LIKELY_PHISHING"
            confidence = "HIGH" if (anchor_mismatches or auth_failed or risky_attachments) else "MEDIUM"
            plain_explanation = (
                "Likely Phishing: Strong deceptive indicators detected, such as deceptive link destinations, "
                "confirmed perimeter authentication failures, dangerous executables, or targeted credential lures."
            )
        elif normalized_score >= 25 or auth_failed:
            verdict = "SUSPICIOUS"
            confidence = "MEDIUM" if not (spf_status == "UNKNOWN" and dkim_status == "UNKNOWN") else "LOW"
            plain_explanation = (
                "Suspicious: Anomalous indicators detected (e.g., routing inconsistencies, failed authentication, "
                "or suspicious attachments). Caution is advised, though conclusive proof of deception requires additional telemetry."
            )
        elif spf_status == "UNKNOWN" and dkim_status == "UNKNOWN" and dmarc_status == "UNKNOWN":
            verdict = "INCONCLUSIVE"
            confidence = "LOW"
            plain_explanation = (
                "Inconclusive: Insufficient or missing authentication telemetry (SPF/DKIM/DMARC headers not present). "
                "While no overt deception was confirmed, the authenticity of the sender cannot be verified from available headers."
            )
        else:
            verdict = "NO_STRONG_INDICATORS_DETECTED"
            confidence = "HIGH" if auth_passed else "MEDIUM"
            plain_explanation = (
                "No Strong Indicators Detected: The email does not exhibit strong signs of deception. "
                "Note: A lack of static indicators does not guarantee the email is safe; targeted or novel attacks may evade static rules."
            )

        return {
            "verdict": verdict,
            "confidence": confidence,
            "score": normalized_score,
            "plain_explanation": plain_explanation,
            "key_indicators": key_indicators,
            "mitigating_factors": mitigating_factors,
            "limitations": limitations,
        }
