"""Forensic RFC 5322 / MIME Email Parser for EviPhish.

Extracts headers, MIME structure, text/HTML bodies, URLs, link text discrepancies,
authentication headers, and attachment metadata using standard library email parser
and BeautifulSoup. Never executes code, opens URLs, or runs attachments.
"""

import email
import email.policy
import email.utils
import hashlib
import re
import urllib.parse
from typing import Any, Optional
from bs4 import BeautifulSoup


class ForensicEmailData:
    """Container holding extracted forensic email data."""
    def __init__(self):
        self.headers: dict[str, Any] = {}
        self.all_headers_raw: list[dict[str, str]] = []
        self.received_chain: list[dict[str, Any]] = []
        self.auth_results: dict[str, Any] = {
            "spf": {"status": "UNKNOWN", "details": None, "source_header": None},
            "dkim": {"status": "UNKNOWN", "details": None, "source_header": None},
            "dmarc": {"status": "UNKNOWN", "details": None, "source_header": None},
            "raw_auth_headers": []
        }
        self.body_plain: str = ""
        self.body_html: str = ""
        self.safe_body_text: str = ""
        self.urls: list[dict[str, Any]] = []
        self.domains: list[str] = []
        self.attachments: list[dict[str, Any]] = []
        self.discrepancies: list[dict[str, Any]] = []
        self.parsing_warnings: list[str] = []


class EmlParser:
    """Forensic email parser that safely extracts and parses untrusted RFC 5322 emails."""

    URL_REGEX = re.compile(
        r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
        re.IGNORECASE
    )

    def parse_bytes(self, raw_bytes: bytes) -> ForensicEmailData:
        """Parse raw email bytes into a structured forensic container."""
        if not raw_bytes or not raw_bytes.strip():
            raise ValueError("Email content is empty.")

        try:
            msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)
        except Exception as e:
            raise ValueError(f"Malformed email structure: {str(e)}")

        data = ForensicEmailData()

        # 1. Extract Raw and Normalized Headers
        self._extract_headers(msg, data)

        # 2. Extract Authentication Headers (SPF, DKIM, DMARC)
        self._extract_authentication(msg, data)

        # 3. Extract Message Bodies & Attachments
        self._extract_payload(msg, data)

        # 4. Extract URLs and Link Discrepancies
        self._extract_urls(data)

        # 5. Extract Domains & Cross-Validate Indicators
        self._extract_domains_and_relationships(data)

        return data

    def _extract_headers(self, msg: email.message.EmailMessage, data: ForensicEmailData):
        """Extract standard headers and preserve raw header list."""
        for key, val in msg.raw_items():
            data.all_headers_raw.append({"name": key, "value": str(val)})

        # Primary headers
        data.headers["subject"] = str(msg.get("Subject", "") or "")
        data.headers["from"] = str(msg.get("From", "") or "")
        data.headers["to"] = str(msg.get("To", "") or "")
        data.headers["cc"] = str(msg.get("Cc", "") or "")
        data.headers["bcc"] = str(msg.get("Bcc", "") or "")
        data.headers["reply_to"] = str(msg.get("Reply-To", "") or "")
        data.headers["return_path"] = str(msg.get("Return-Path", "") or "")
        data.headers["message_id"] = str(msg.get("Message-ID", "") or "")
        data.headers["date"] = str(msg.get("Date", "") or "")

        # Parse addresses
        from_name, from_addr = email.utils.parseaddr(data.headers["from"])
        data.headers["from_parsed"] = {"name": from_name, "address": from_addr}

        reply_name, reply_addr = email.utils.parseaddr(data.headers["reply_to"])
        data.headers["reply_to_parsed"] = {"name": reply_name, "address": reply_addr}

        return_name, return_addr = email.utils.parseaddr(data.headers["return_path"])
        data.headers["return_path_parsed"] = {"name": return_name, "address": return_addr}

        to_addrs = email.utils.getaddresses([data.headers["to"]])
        data.headers["to_parsed"] = [{"name": n, "address": a} for n, a in to_addrs if a]

        # Received headers chain (ordered from top to bottom)
        received_headers = msg.get_all("Received", [])
        for idx, rec in enumerate(received_headers):
            rec_str = str(rec).strip()
            # Basic parsing of 'from ... by ... ; date'
            data.received_chain.append({
                "hop": idx + 1,
                "raw": rec_str,
                "summary": rec_str.split(";")[0].replace("\n", " ").strip() if ";" in rec_str else rec_str
            })

    def _extract_authentication(self, msg: email.message.EmailMessage, data: ForensicEmailData):
        """Extract explicit SPF, DKIM, and DMARC results from authentication headers.
        
        Strict Forensic Rule: If no header is present, status is UNKNOWN.
        We do not invent passes or failures.
        """
        auth_headers = msg.get_all("Authentication-Results", [])
        arc_headers = msg.get_all("ARC-Authentication-Results", [])
        received_spf = msg.get_all("Received-SPF", [])

        combined_auth_headers = [str(h) for h in auth_headers + arc_headers]
        data.auth_results["raw_auth_headers"] = combined_auth_headers

        # Check SPF in Authentication-Results or Received-SPF
        for h in combined_auth_headers:
            spf_match = re.search(r'\bspf=([a-zA-Z]+)(?:\s*\(([^)]+)\))?', h, re.IGNORECASE)
            if spf_match and data.auth_results["spf"]["status"] == "UNKNOWN":
                data.auth_results["spf"] = {
                    "status": spf_match.group(1).upper(),
                    "details": spf_match.group(2) or spf_match.group(0),
                    "source_header": "Authentication-Results"
                }

            dkim_match = re.search(r'\bdkim=([a-zA-Z]+)(?:\s*\(([^)]+)\))?', h, re.IGNORECASE)
            if dkim_match and data.auth_results["dkim"]["status"] == "UNKNOWN":
                data.auth_results["dkim"] = {
                    "status": dkim_match.group(1).upper(),
                    "details": dkim_match.group(2) or dkim_match.group(0),
                    "source_header": "Authentication-Results"
                }

            dmarc_match = re.search(r'\bdmarc=([a-zA-Z]+)(?:\s*\(([^)]+)\))?', h, re.IGNORECASE)
            if dmarc_match and data.auth_results["dmarc"]["status"] == "UNKNOWN":
                data.auth_results["dmarc"] = {
                    "status": dmarc_match.group(1).upper(),
                    "details": dmarc_match.group(2) or dmarc_match.group(0),
                    "source_header": "Authentication-Results"
                }

        # Check Received-SPF if still UNKNOWN
        if data.auth_results["spf"]["status"] == "UNKNOWN" and received_spf:
            rec_spf_str = str(received_spf[0]).strip()
            status_match = re.match(r'^([a-zA-Z]+)', rec_spf_str)
            if status_match:
                data.auth_results["spf"] = {
                    "status": status_match.group(1).upper(),
                    "details": rec_spf_str,
                    "source_header": "Received-SPF"
                }

    def _extract_payload(self, msg: email.message.EmailMessage, data: ForensicEmailData):
        """Walk MIME structure and safely extract bodies and attachments."""
        plain_parts = []
        html_parts = []

        for part in msg.walk():
            # Check content disposition
            disposition = part.get_content_disposition()
            filename = part.get_filename()
            content_type = part.get_content_type()

            if disposition == "attachment" or filename:
                # Process attachment metadata safely without execution
                safe_name = filename or f"unnamed_attachment_{len(data.attachments) + 1}"
                payload_bytes = part.get_payload(decode=True) or b""
                size_bytes = len(payload_bytes)
                sha256_hash = hashlib.sha256(payload_bytes).hexdigest()

                data.attachments.append({
                    "filename": safe_name,
                    "content_type": content_type,
                    "size_bytes": size_bytes,
                    "sha256": sha256_hash,
                    "disposition": disposition or "attachment"
                })
                continue

            if content_type == "text/plain":
                try:
                    payload = part.get_content()
                    if isinstance(payload, str):
                        plain_parts.append(payload)
                except Exception as e:
                    data.parsing_warnings.append(f"Failed decoding text/plain part: {str(e)}")

            elif content_type == "text/html":
                try:
                    payload = part.get_content()
                    if isinstance(payload, str):
                        html_parts.append(payload)
                except Exception as e:
                    data.parsing_warnings.append(f"Failed decoding text/html part: {str(e)}")

        data.body_plain = "\n\n".join(plain_parts)
        data.body_html = "\n\n".join(html_parts)

        # Generate safe text from HTML if plain text is empty
        if data.body_html:
            try:
                soup = BeautifulSoup(data.body_html, "html.parser")
                # Remove active elements
                for element in soup(["script", "style", "iframe", "object", "embed"]):
                    element.decompose()
                data.safe_body_text = soup.get_text(separator="\n", strip=True)
            except Exception as e:
                data.safe_body_text = data.body_plain or ""
                data.parsing_warnings.append(f"HTML text extraction warning: {str(e)}")
        else:
            data.safe_body_text = data.body_plain

    def _extract_urls(self, data: ForensicEmailData):
        """Extract URLs from plain text and HTML, detecting text vs destination discrepancies."""
        extracted_urls_map: dict[str, dict[str, Any]] = {}

        # 1. Plain text URLs
        if data.body_plain:
            for match in self.URL_REGEX.finditer(data.body_plain):
                url = match.group(0).rstrip(".,)>\"'")
                if url not in extracted_urls_map:
                    extracted_urls_map[url] = {
                        "url": url,
                        "source": "Plain Text Body",
                        "display_text": url,
                        "is_discrepancy": False,
                        "domain": self._extract_domain(url)
                    }

        # 2. HTML <a> tags (capture displayed text vs actual destination href)
        if data.body_html:
            try:
                soup = BeautifulSoup(data.body_html, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    display_text = a_tag.get_text(strip=True)

                    if not href.startswith("http://") and not href.startswith("https://"):
                        continue

                    target_domain = self._extract_domain(href)
                    is_discrepancy = False
                    discrepancy_desc = None

                    # Check if displayed text looks like a URL but points to another domain
                    if re.match(r'^(https?://|www\.)', display_text, re.IGNORECASE):
                        apparent_url = display_text if display_text.startswith("http") else f"http://{display_text}"
                        apparent_domain = self._extract_domain(apparent_url)
                        if apparent_domain and target_domain and apparent_domain.lower() != target_domain.lower():
                            is_discrepancy = True
                            discrepancy_desc = (
                                f"Displayed anchor text suggests '{apparent_domain}' but destination is '{target_domain}'"
                            )
                            data.discrepancies.append({
                                "type": "ANCHOR_TEXT_DESTINATION_MISMATCH",
                                "display_text": display_text,
                                "destination_url": href,
                                "apparent_domain": apparent_domain,
                                "target_domain": target_domain,
                                "description": discrepancy_desc
                            })

                    extracted_urls_map[href] = {
                        "url": href,
                        "source": "HTML Body <a> Tag",
                        "display_text": display_text or href,
                        "is_discrepancy": is_discrepancy,
                        "discrepancy_description": discrepancy_desc,
                        "domain": target_domain
                    }
            except Exception as e:
                data.parsing_warnings.append(f"URL extraction from HTML error: {str(e)}")

        data.urls = list(extracted_urls_map.values())

    def _extract_domains_and_relationships(self, data: ForensicEmailData):
        """Extract domains from sender, return-path, reply-to, and URLs."""
        domain_set = set()

        def add_addr_domain(addr: str):
            if "@" in addr:
                dom = addr.split("@")[-1].strip().lower().rstrip(">")
                if dom:
                    domain_set.add(dom)

        from_addr = data.headers.get("from_parsed", {}).get("address", "")
        reply_addr = data.headers.get("reply_to_parsed", {}).get("address", "")
        return_addr = data.headers.get("return_path_parsed", {}).get("address", "")

        add_addr_domain(from_addr)
        add_addr_domain(reply_addr)
        add_addr_domain(return_addr)

        # Check for From vs Reply-To / Return-Path domain mismatch
        from_dom = from_addr.split("@")[-1].lower() if "@" in from_addr else None
        reply_dom = reply_addr.split("@")[-1].lower() if "@" in reply_addr else None
        return_dom = return_addr.split("@")[-1].lower() if "@" in return_addr else None

        if from_dom and reply_dom and from_dom != reply_dom:
            data.discrepancies.append({
                "type": "FROM_REPLYTO_DOMAIN_MISMATCH",
                "from_domain": from_dom,
                "reply_to_domain": reply_dom,
                "description": f"Sender domain '{from_dom}' does not match Reply-To domain '{reply_dom}'"
            })

        if from_dom and return_dom and from_dom != return_dom:
            data.discrepancies.append({
                "type": "FROM_RETURNPATH_DOMAIN_MISMATCH",
                "from_domain": from_dom,
                "return_path_domain": return_dom,
                "description": f"Sender domain '{from_dom}' does not match Return-Path domain '{return_dom}'"
            })

        for u in data.urls:
            dom = u.get("domain")
            if dom:
                domain_set.add(dom.lower())

        data.domains = sorted(list(domain_set))

    def _extract_domain(self, url: str) -> Optional[str]:
        """Safely extract hostname domain from a URL string."""
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.netloc.split(":")[0].strip()
            return host if host else None
        except Exception:
            return None
