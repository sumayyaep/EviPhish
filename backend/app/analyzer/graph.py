"""Evidence Graph Builder for React Flow.

Constructs interactive nodes and labeled edges representing verified relationships
between the email, sender, recipients, domains, URLs, attachments, and authentication records.
Only connects indicators backed by actual investigation data.
"""

from typing import Any


class EvidenceGraphBuilder:
    """Builds React Flow compatible graph representations from parsed forensics data."""

    def build_graph(self, parsed_data: dict[str, Any], evidence_items: list[dict[str, Any]]) -> dict[str, Any]:
        """Construct nodes and edges for React Flow."""
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        node_id_map: set[str] = set()

        def add_node(node_id: str, label: str, category: str, x: int, y: int, extra: dict[str, Any] = None):
            if node_id in node_id_map:
                return
            node_id_map.add(node_id)
            nodes.append({
                "id": node_id,
                "type": "custom",
                "position": {"x": x, "y": y},
                "data": {
                    "label": label,
                    "category": category,
                    **(extra or {})
                }
            })

        def add_edge(edge_id: str, source: str, target: str, label: str, style_type: str = "default"):
            edges.append({
                "id": edge_id,
                "source": source,
                "target": target,
                "label": label,
                "type": "smoothstep",
                "animated": style_type == "alert",
                "data": {"style_type": style_type}
            })

        headers = parsed_data.get("headers", {})
        auth = parsed_data.get("auth_results", {})
        urls = parsed_data.get("urls", [])
        attachments = parsed_data.get("attachments", [])
        discrepancies = parsed_data.get("discrepancies", [])

        # 1. Root Email Node
        subject = headers.get("subject", "Email Message")
        add_node("email_root", f"Subject: {subject[:40]}...", "EMAIL", 400, 40, {
            "date": headers.get("date"),
            "message_id": headers.get("message_id")
        })

        # 2. Sender Node
        sender_addr = headers.get("from_parsed", {}).get("address") or headers.get("from", "Unknown Sender")
        sender_name = headers.get("from_parsed", {}).get("name")
        sender_label = f"{sender_name} <{sender_addr}>" if sender_name else sender_addr
        add_node("sender_node", sender_label, "SENDER", 150, 180, {"address": sender_addr})
        add_edge("edge_email_sender", "email_root", "sender_node", "sent by")

        # Sender Domain
        if "@" in sender_addr:
            sender_dom = sender_addr.split("@")[-1].strip().lower().rstrip(">")
            sender_dom_id = f"dom_{sender_dom}"
            add_node(sender_dom_id, sender_dom, "DOMAIN", 50, 320, {"domain": sender_dom})
            add_edge(f"edge_sender_{sender_dom_id}", "sender_node", sender_dom_id, "uses domain")

        # 3. Recipient Node
        recipient = headers.get("to", "Unknown Recipient")
        add_node("recipient_node", recipient[:45], "RECIPIENT", 650, 180, {"to": recipient})
        add_edge("edge_email_recipient", "email_root", "recipient_node", "delivered to")

        # 4. Authentication Nodes
        auth_x = 220
        for auth_type in ["spf", "dkim", "dmarc"]:
            auth_info = auth.get(auth_type, {})
            status = auth_info.get("status", "UNKNOWN")
            auth_node_id = f"auth_{auth_type}"
            add_node(auth_node_id, f"{auth_type.upper()}: {status}", "AUTH", auth_x, 320, {
                "auth_type": auth_type,
                "status": status,
                "source": auth_info.get("source_header")
            })
            add_edge(f"edge_email_{auth_node_id}", "email_root", auth_node_id, f"auth {auth_type.upper()}")
            auth_x += 160

        # 5. Attachment Nodes
        att_y = 460
        for idx, att in enumerate(attachments):
            att_id = f"att_{idx}"
            att_name = att.get("filename", "file")
            add_node(att_id, f"{att_name} ({att.get('size_bytes', 0)} B)", "ATTACHMENT", 750, att_y, att)
            add_edge(f"edge_email_{att_id}", "email_root", att_id, "contains attachment")
            att_y += 100

        # 6. URL & Domain Nodes
        url_x = 350
        url_y = 480
        for idx, u in enumerate(urls[:6]):  # Cap initial visual graph to 6 URLs for layout clarity
            url_str = u.get("url", "")
            url_dom = u.get("domain", "")
            url_node_id = f"url_{idx}"
            display_text = u.get("display_text", url_str)
            is_disc = u.get("is_discrepancy", False)

            add_node(url_node_id, display_text[:35] + ("..." if len(display_text) > 35 else ""), "URL", url_x, url_y, {
                "full_url": url_str,
                "domain": url_dom,
                "is_discrepancy": is_disc
            })
            add_edge(f"edge_email_{url_node_id}", "email_root", url_node_id, "contains link", "alert" if is_disc else "default")

            if url_dom:
                dom_node_id = f"dom_{url_dom}"
                add_node(dom_node_id, url_dom, "DOMAIN", url_x + 50, url_y + 120, {"domain": url_dom})
                add_edge(f"edge_url_{url_node_id}_{dom_node_id}", url_node_id, dom_node_id, "hosts destination")

            url_x += 200
            if (idx + 1) % 2 == 0:
                url_x = 350
                url_y += 220

        # 7. Discrepancy Alert Connections
        for idx, disc in enumerate(discrepancies):
            if disc.get("type") == "ANCHOR_TEXT_DESTINATION_MISMATCH":
                disc_node_id = f"disc_{idx}"
                add_node(disc_node_id, "Anchor / Link Mismatch", "ALERT", 550, 280, disc)
                add_edge(f"edge_disc_{idx}", "email_root", disc_node_id, "deceptive link text", "alert")

        return {"nodes": nodes, "edges": edges}
