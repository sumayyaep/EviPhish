"""Attack Sequence Reconstruction for EviPhish.

Reconstructs an evidence-backed chronological sequence of observed events,
clearly partitioned from analyst inferences and unverified attack hypotheses.
Never presumes compromise, credential theft, or malware execution without telemetry.
"""

from typing import Any


class AttackReconstructionBuilder:
    """Builds a structured chronological reconstruction of the email lifecycle."""

    def build_reconstruction(self, parsed_data: dict[str, Any], evidence_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Construct timeline events separating Observed facts, Inferred patterns, and Unverifiable hypotheses."""
        timeline: list[dict[str, Any]] = []
        headers = parsed_data.get("headers", {})
        received_chain = parsed_data.get("received_chain", [])
        urls = parsed_data.get("urls", [])
        attachments = parsed_data.get("attachments", [])
        auth = parsed_data.get("auth_results", {})
        discrepancies = parsed_data.get("discrepancies", [])

        # Step 1: Origination & Message Composition (Observed)
        origination_date = headers.get("date", "Date not specified in headers")
        sender = headers.get("from", "Unspecified sender")
        timeline.append({
            "step": 1,
            "stage": "Origination",
            "category": "OBSERVED",
            "timestamp": origination_date,
            "title": "Email Formatted & Declared by Client",
            "description": f"Message composed with Subject '{headers.get('subject', 'None')}' declared as sent from '{sender}'.",
            "evidence_reference": "Header: Date & From",
            "is_hypothetical": False,
            "status": "VERIFIED_IN_RECORD"
        })

        # Step 2: Relay Transmission Hops (Observed)
        if received_chain:
            # The earliest relay hop is at the bottom of Received headers list
            earliest_hop = received_chain[-1]
            latest_hop = received_chain[0]
            timeline.append({
                "step": 2,
                "stage": "Transit & Relay",
                "category": "OBSERVED",
                "timestamp": "During transit",
                "title": f"Traversed {len(received_chain)} Relay Hop(s)",
                "description": f"Transmitted from earliest logged MTA ({earliest_hop.get('summary')[:70]}...) to receiving MX ({latest_hop.get('summary')[:70]}...).",
                "evidence_reference": "Header: Received (Chain)",
                "is_hypothetical": False,
                "status": "VERIFIED_IN_RECORD"
            })

        # Step 3: Perimeter Authentication Check (Observed)
        spf_status = auth.get("spf", {}).get("status", "UNKNOWN")
        dkim_status = auth.get("dkim", {}).get("status", "UNKNOWN")
        dmarc_status = auth.get("dmarc", {}).get("status", "UNKNOWN")
        timeline.append({
            "step": 3,
            "stage": "Perimeter Inspection",
            "category": "OBSERVED",
            "timestamp": "At time of delivery",
            "title": "Perimeter Authentication Evaluation",
            "description": f"Receiving gateway recorded authentication: SPF={spf_status}, DKIM={dkim_status}, DMARC={dmarc_status}.",
            "evidence_reference": "Header: Authentication-Results",
            "is_hypothetical": False,
            "status": "VERIFIED_IN_RECORD"
        })

        # Step 4: Deceptive Indicators Detection (Inferred)
        if discrepancies:
            disc_summaries = [d.get("description", "") for d in discrepancies]
            timeline.append({
                "step": 4,
                "stage": "Analysis & Heuristics",
                "category": "INFERRED",
                "timestamp": "Post-delivery analysis",
                "title": "Deceptive Indicators & Header Inconsistencies Detected",
                "description": f"Forensic analysis identified {len(discrepancies)} mismatch pattern(s): {'; '.join(disc_summaries)}.",
                "evidence_reference": "Discrepancy Analysis",
                "is_hypothetical": False,
                "status": "INFERRED_FROM_FACTS"
            })

        # Step 5: Potential User Interaction (Unverifiable from static email)
        timeline.append({
            "step": 5,
            "stage": "User Interaction",
            "category": "UNKNOWN / UNVERIFIABLE",
            "timestamp": "Post-delivery (Unknown)",
            "title": "User Interaction Status (Unknown)",
            "description": (
                "No telemetry is available to indicate whether the user read the email, clicked embedded links "
                f"({len(urls)} link(s) found), or opened attachments ({len(attachments)} attachment(s) found). "
                "Such conclusions strictly require proxy/EDR or mail access logs."
            ),
            "evidence_reference": "Missing Endpoint / Proxy Telemetry",
            "is_hypothetical": True,
            "status": "UNVERIFIABLE"
        })

        # Step 6: Exploitation or Compromise (Unverifiable from static email)
        timeline.append({
            "step": 6,
            "stage": "Exploitation / Compromise",
            "category": "UNKNOWN / UNVERIFIABLE",
            "timestamp": "Post-delivery (Unknown)",
            "title": "Compromise or Credential Submission (Unestablished)",
            "description": (
                "Defensive Forensics Rule: Never claim compromise or credential leakage without verifiable corroboration. "
                "The email represents a delivery vector, but payload execution or victim compromise is not established by static email forensics."
            ),
            "evidence_reference": "Requires SIEM/Identity Provider Logs",
            "is_hypothetical": True,
            "status": "UNVERIFIABLE"
        })

        return timeline
