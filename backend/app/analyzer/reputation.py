import re
import httpx
from datetime import datetime, UTC
from backend.app.schemas.reputation import ReputationResult, SyntaxValidation

# Basic Regex for Syntax
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

class EmailReputationChecker:
    def __init__(self, provider_name: str = "none", api_key: str | None = None):
        self.provider_name = provider_name
        self.api_key = api_key

    def _validate_syntax(self, email: str) -> SyntaxValidation:
        email = email.strip()
        if not EMAIL_REGEX.match(email):
            return SyntaxValidation(is_valid_format=False, error="Invalid email address format.")
        
        parts = email.split('@')
        domain = parts[-1].lower()
        normalized = f"{parts[0]}@{domain}"
        
        return SyntaxValidation(
            is_valid_format=True,
            normalized_email=normalized,
            domain=domain
        )

    def check(self, email: str, consent_given: bool) -> ReputationResult:
        syntax = self._validate_syntax(email)
        
        if not syntax.is_valid_format:
            return ReputationResult(
                address=email,
                syntax=syntax,
                verdict="INCONCLUSIVE",
                confidence="LOW",
                explanation="The provided string is not a valid email address.",
                limitations=["Cannot perform reputation lookup on malformed inputs."]
            )

        if not consent_given:
            return ReputationResult(
                address=syntax.normalized_email or email,
                syntax=syntax,
                verdict="INCONCLUSIVE",
                confidence="LOW",
                explanation="No external queries were performed because explicit user consent was not granted.",
                limitations=["Reputation checks require external API queries which are disabled without consent."]
            )

        if not self.api_key or self.provider_name.lower() != "emailrep":
            return ReputationResult(
                address=syntax.normalized_email or email,
                syntax=syntax,
                verdict="INCONCLUSIVE",
                confidence="LOW",
                explanation="EmailRep provider is not configured. Syntax validation indicates it is a valid format, but reputation is unknown.",
                limitations=[
                    "Syntax validation does not prove the mailbox exists.",
                    "System administrator needs to configure EMAILREP_API_KEY environment variable."
                ]
            )

        return self._query_emailrep(syntax)

    def _query_emailrep(self, syntax: SyntaxValidation) -> ReputationResult:
        normalized_email = syntax.normalized_email or ""
        url = f"https://emailrep.io/{normalized_email}"
        headers = {
            "Key": self.api_key or "",
            "User-Agent": "EviPhish/0.1.0"
        }
        
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(url, headers=headers)
                
                if response.status_code == 429:
                    return self._build_error_result(normalized_email, syntax, "Rate limit exceeded for EmailRep API.")
                if response.status_code == 401:
                    return self._build_error_result(normalized_email, syntax, "Invalid or unauthorized API key for EmailRep.")
                
                response.raise_for_status()
                data = response.json()
                
                reputation = data.get("reputation", "none")
                suspicious = data.get("suspicious", False)
                details = data.get("details", {})
                references = data.get("references", 0)
                
                findings = []
                limitations = [
                    "Reputation is not proof of identity.",
                    "Attackers often spoof known domains."
                ]
                
                is_blacklisted = details.get("blacklisted", False)
                malicious_activity = details.get("malicious_activity", False)
                credentials_leaked = details.get("credentials_leaked", False)
                
                # Conservative Mapping
                if suspicious or is_blacklisted or malicious_activity:
                    verdict = "REPORTED_SUSPICIOUS"
                    confidence = "HIGH" if references > 0 else "MEDIUM"
                    explanation = "The address has been reported by threat intelligence sources as suspicious or blacklisted. Note that a reported address may also be spoofed or compromised; reputation does not prove who sent a message."
                    
                    if is_blacklisted:
                        findings.append(f"[{datetime.now(UTC).isoformat()}Z] Address is blacklisted.")
                    if malicious_activity:
                        findings.append(f"[{datetime.now(UTC).isoformat()}Z] Address observed in recent malicious activity.")
                elif reputation in ["high", "medium"] and not suspicious:
                    verdict = "NO_REPORTS_FOUND"
                    confidence = "LOW"
                    explanation = "No negative reports were found for this address in the queried intelligence sources."
                    if credentials_leaked:
                        findings.append("Note: Credentials for this address have been leaked in past breaches.")
                    limitations.extend([
                        "Absence of malicious reports does not guarantee safety.",
                        "Targeted or novel campaigns will not appear in public reputation lists.",
                        "Free email providers often have 'high' reputation; this does not mean a specific address is safe."
                    ])
                else:
                    verdict = "INCONCLUSIVE"
                    confidence = "LOW"
                    explanation = "The provider did not return sufficient evidence to declare this address safe or suspicious."

                if references > 0:
                    findings.append(f"Referenced {references} times in EmailRep data sources.")
                    
                return ReputationResult(
                    address=normalized_email,
                    syntax=syntax,
                    verdict=verdict,
                    sources_checked=["EmailRep.io"],
                    findings=findings,
                    confidence=confidence,
                    explanation=explanation,
                    limitations=limitations,
                    metadata={"emailrep_reputation": reputation}
                )
                
        except httpx.TimeoutException:
            return self._build_error_result(
                normalized_email, syntax,
                "The external provider timed out before returning a result."
            )
        except httpx.RequestError as exc:
            return self._build_error_result(
                normalized_email, syntax,
                f"An error occurred while requesting data from EmailRep: {exc}"
            )
        except Exception as exc:
            return self._build_error_result(
                normalized_email, syntax,
                "An unexpected error occurred processing the EmailRep response."
            )

    def _build_error_result(self, email: str, syntax: SyntaxValidation, explanation: str) -> ReputationResult:
        return ReputationResult(
            address=email,
            syntax=syntax,
            verdict="INCONCLUSIVE",
            sources_checked=["EmailRep.io"],
            confidence="LOW",
            explanation=explanation,
            limitations=["Reputation providers may be occasionally unavailable or ratelimited."]
        )
