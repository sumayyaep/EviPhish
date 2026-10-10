"""Evidence Classifier for EviPhish.

Transforms parsed forensic email data into atomic, defensible evidence items
with classifications (OBSERVED, INFERRED, UNKNOWN), limitations, and explanations.
Strictly separates direct observations from analyst hypotheses.
"""

from typing import Any
from backend.app.parser.eml_parser import ForensicEmailData


class EvidenceClassifier:
    """Classifies forensic findings adhering to the Evidence-First principle."""

    def classify_findings(self, data: ForensicEmailData) -> list[dict[str, Any]]:
        """Generate a list of structured, classified evidence items."""
        evidence_list: list[dict[str, Any]] = []
        counter = 1

        def next_id() -> str:
            nonlocal counter
            eid = f"EVID-{counter:03d}"
            counter += 1
            return eid

        # 1. From Header
        from_str = data.headers.get("from", "")
        if from_str:
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "HEADER_FROM",
                "observed_value": from_str,
                "source_location": "Header: From",
                "classification": "OBSERVED",
                "explanation": "Declared sender address in RFC 5322 header.",
                "limitations": (
                    "The From header is client-provided and easily forged unless validated by SPF/DKIM "
                    "with strict DMARC alignment."
                ),
                "confidence_level": "HIGH",
                "extra_data": data.headers.get("from_parsed", {})
            })

        # 2. Reply-To Header
        reply_to_str = data.headers.get("reply_to", "")
        if reply_to_str:
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "HEADER_REPLY_TO",
                "observed_value": reply_to_str,
                "source_location": "Header: Reply-To",
                "classification": "OBSERVED",
                "explanation": "Declared destination address for user replies.",
                "limitations": (
                    "May differ legitimately in newsletters or helpdesks, but asymmetric reply addresses "
                    "can also redirect responses to attacker mailboxes."
                ),
                "confidence_level": "HIGH",
                "extra_data": data.headers.get("reply_to_parsed", {})
            })

        # 3. Return-Path Header
        return_path_str = data.headers.get("return_path", "")
        if return_path_str:
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "HEADER_RETURN_PATH",
                "observed_value": return_path_str,
                "source_location": "Header: Return-Path",
                "classification": "OBSERVED",
                "explanation": "Envelope sender (RFC 5321 Mail From) recorded by the receiving mail server.",
                "limitations": (
                    "Set during the SMTP envelope exchange. Only trustworthy if the receiving MTA is trusted."
                ),
                "confidence_level": "HIGH",
                "extra_data": data.headers.get("return_path_parsed", {})
            })

        # 4. Subject Header
        subject_str = data.headers.get("subject", "")
        if subject_str:
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "HEADER_SUBJECT",
                "observed_value": subject_str,
                "source_location": "Header: Subject",
                "classification": "OBSERVED",
                "explanation": "Subject line text presented to recipient.",
                "limitations": "Subject text can simulate urgent security warnings or administrative alerts.",
                "confidence_level": "HIGH"
            })

        # 5. Date Header
        date_str = data.headers.get("date", "")
        if date_str:
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "HEADER_DATE",
                "observed_value": date_str,
                "source_location": "Header: Date",
                "classification": "OBSERVED",
                "explanation": "Origination timestamp declared by the sender system.",
                "limitations": "Sender system clock may be desynchronized or intentionally altered.",
                "confidence_level": "MEDIUM"
            })

        # 6. Message-ID Header
        mid_str = data.headers.get("message_id", "")
        if mid_str:
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "HEADER_MESSAGE_ID",
                "observed_value": mid_str,
                "source_location": "Header: Message-ID",
                "classification": "OBSERVED",
                "explanation": "Message identifier assigned by generating client or originating MTA.",
                "limitations": "Can be crafted or omitted in non-standard software.",
                "confidence_level": "HIGH"
            })

        # 7. Received Chain Hops
        if data.received_chain:
            hops_count = len(data.received_chain)
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "RECEIVED_HOPS",
                "observed_value": f"{hops_count} relay hop(s) recorded in Received headers.",
                "source_location": "Header: Received (Chain)",
                "classification": "OBSERVED",
                "explanation": "Ordered MTA relay hops traversed by the message prior to mailbox delivery.",
                "limitations": (
                    "Only the topmost Received header inserted by your own perimeter mail server is authenticated. "
                    "Preceding headers can be forged by upstream relays."
                ),
                "confidence_level": "HIGH",
                "extra_data": {"hops": data.received_chain}
            })

        # 8. SPF Authentication
        spf_info = data.auth_results.get("spf", {})
        spf_status = spf_info.get("status", "UNKNOWN")
        if spf_status != "UNKNOWN":
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "AUTH_SPF",
                "observed_value": f"SPF={spf_status} ({spf_info.get('details') or 'No details'})",
                "source_location": f"Header: {spf_info.get('source_header', 'Authentication-Results')}",
                "classification": "OBSERVED",
                "explanation": f"Explicit SPF verification recorded in headers: {spf_status}.",
                "limitations": (
                    "Recorded result from receiving MTA at delivery time. Independent live DNS SPF record "
                    "evaluation was not performed to prevent telemetry leakage."
                ),
                "confidence_level": "HIGH",
                "extra_data": spf_info
            })
        else:
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "AUTH_SPF",
                "observed_value": "SPF result not recorded in headers.",
                "source_location": "Header: Authentication-Results",
                "classification": "UNKNOWN",
                "explanation": "No SPF authentication header was found in the provided email file.",
                "limitations": "Cannot establish whether SPF check passed, failed, or was unconfigured by recipient MTA.",
                "confidence_level": "LOW"
            })

        # 9. DKIM Authentication
        dkim_info = data.auth_results.get("dkim", {})
        dkim_status = dkim_info.get("status", "UNKNOWN")
        if dkim_status != "UNKNOWN":
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "AUTH_DKIM",
                "observed_value": f"DKIM={dkim_status} ({dkim_info.get('details') or 'No details'})",
                "source_location": f"Header: {dkim_info.get('source_header', 'Authentication-Results')}",
                "classification": "OBSERVED",
                "explanation": f"Explicit DKIM signature verification recorded in headers: {dkim_status}.",
                "limitations": "Verifies that email body and specified headers matched signature upon initial delivery.",
                "confidence_level": "HIGH",
                "extra_data": dkim_info
            })
        else:
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "AUTH_DKIM",
                "observed_value": "DKIM result not recorded in headers.",
                "source_location": "Header: Authentication-Results",
                "classification": "UNKNOWN",
                "explanation": "No DKIM signature verification header was present.",
                "limitations": "Cannot verify cryptographic authenticity of headers without public key records.",
                "confidence_level": "LOW"
            })

        # 10. DMARC Authentication
        dmarc_info = data.auth_results.get("dmarc", {})
        dmarc_status = dmarc_info.get("status", "UNKNOWN")
        if dmarc_status != "UNKNOWN":
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "AUTH_DMARC",
                "observed_value": f"DMARC={dmarc_status} ({dmarc_info.get('details') or 'No details'})",
                "source_location": f"Header: {dmarc_info.get('source_header', 'Authentication-Results')}",
                "classification": "OBSERVED",
                "explanation": f"Explicit DMARC alignment status recorded in headers: {dmarc_status}.",
                "limitations": "Relies on receiving server's policy enforcement rules at delivery time.",
                "confidence_level": "HIGH",
                "extra_data": dmarc_info
            })
        else:
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "AUTH_DMARC",
                "observed_value": "DMARC result not recorded in headers.",
                "source_location": "Header: Authentication-Results",
                "classification": "UNKNOWN",
                "explanation": "No DMARC validation outcome was recorded in headers.",
                "limitations": "Live DNS query for _dmarc policy record would be needed for independent verification.",
                "confidence_level": "LOW"
            })

        # 11. URLs Extracted
        for url_item in data.urls:
            url_str = url_item.get("url", "")
            domain = url_item.get("domain", "")
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "BODY_URL",
                "observed_value": url_str,
                "source_location": url_item.get("source", "Body"),
                "classification": "OBSERVED",
                "explanation": f"Hyperlink pointing to domain '{domain}'.",
                "limitations": (
                    "Static presence of URL in message body. No automated HTTP request was initiated to protect analyst "
                    "safety and prevent alerting threat actors."
                ),
                "confidence_level": "HIGH",
                "extra_data": url_item
            })

        # 12. Discrepancies (Inferred Findings)
        for disc in data.discrepancies:
            disc_type = disc.get("type", "DISCREPANCY")
            if disc_type == "ANCHOR_TEXT_DESTINATION_MISMATCH":
                evidence_list.append({
                    "id": next_id(),
                    "evidence_type": "URL_TEXT_MISMATCH",
                    "observed_value": (
                        f"Anchor Text: '{disc.get('display_text')}' -> Actual Destination: '{disc.get('destination_url')}'"
                    ),
                    "source_location": "HTML Body <a> Tag",
                    "classification": "INFERRED",
                    "explanation": (
                        "Displayed anchor text misrepresents the actual link target. Often employed to deceive users "
                        "into believing they are navigating to a familiar domain."
                    ),
                    "limitations": (
                        "Some enterprise link-rewriting security tools (e.g., Proofpoint, Microsoft Defender Safe Links) "
                        "or marketing redirectors rewrite URLs legitimately."
                    ),
                    "confidence_level": "HIGH",
                    "extra_data": disc
                })
            elif disc_type in ("FROM_REPLYTO_DOMAIN_MISMATCH", "FROM_RETURNPATH_DOMAIN_MISMATCH"):
                evidence_list.append({
                    "id": next_id(),
                    "evidence_type": "DOMAIN_ALIGNMENT_MISMATCH",
                    "observed_value": disc.get("description", "Domain mismatch"),
                    "source_location": "Header Domain Comparison",
                    "classification": "INFERRED",
                    "explanation": "Sender display domain does not align with routing envelope or reply addresses.",
                    "limitations": (
                        "Third-party notification engines and mailing lists often use distinct return-path or reply domains. "
                        "SPF/DKIM alignment should be evaluated alongside this finding."
                    ),
                    "confidence_level": "MEDIUM",
                    "extra_data": disc
                })

        # 13. Attachments
        for att in data.attachments:
            evidence_list.append({
                "id": next_id(),
                "evidence_type": "ATTACHMENT",
                "observed_value": f"{att.get('filename')} ({att.get('content_type')}, {att.get('size_bytes')} bytes)",
                "source_location": "MIME Part",
                "classification": "OBSERVED",
                "explanation": f"Email attachment with SHA256: {att.get('sha256')}.",
                "limitations": (
                    "Static metadata only. File content was not executed or detonated in an active sandbox."
                ),
                "confidence_level": "HIGH",
                "extra_data": att
            })

        return evidence_list
