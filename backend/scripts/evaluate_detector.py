import sys
from pathlib import Path

# Add the project root to the python path so imports work correctly
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

from backend.app.parser.eml_parser import ForensicEmailData
from backend.app.analyzer.classifier import EvidenceClassifier
from backend.app.analyzer.detector import PhishingDetector

def create_mock_parsed_email(
    spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN",
    reply_mismatch=False, return_mismatch=False,
    body_text="", has_html_att=False, has_exe_att=False,
    anchor_mismatch=False, urls=None, html_filename="invoice.html"
) -> ForensicEmailData:
    data = ForensicEmailData()
    data.auth_results["spf"]["status"] = spf
    data.auth_results["dkim"]["status"] = dkim
    data.auth_results["dmarc"]["status"] = dmarc
    
    if reply_mismatch:
        data.discrepancies.append({"type": "FROM_REPLYTO_DOMAIN_MISMATCH", "description": "Reply-To differs"})
    if return_mismatch:
        data.discrepancies.append({"type": "FROM_RETURNPATH_DOMAIN_MISMATCH", "description": "Return-Path differs"})
    if anchor_mismatch:
        data.discrepancies.append({"type": "ANCHOR_TEXT_DESTINATION_MISMATCH", "apparent_domain": "trusted.com", "target_domain": "evil.com"})
        
    data.body_plain = body_text
    data.safe_body_text = body_text
    
    if has_html_att:
        data.attachments.append({"filename": html_filename, "content_type": "text/html", "size_bytes": 100, "sha256": "x"})
    if has_exe_att:
        data.attachments.append({"filename": "invoice.exe", "content_type": "application/x-msdownload", "size_bytes": 100, "sha256": "x"})
        
    if urls:
        for u in urls:
            data.urls.append({"url": u, "domain": "example.com"})
            
    return data


# --- Define the Dataset ---
# Ground truth labels: BENIGN, PHISHING, AMBIGUOUS

DATASET = [
    # --- PHISHING CASES (Expected: LIKELY_PHISHING or SUSPICIOUS) ---
    {"id": "P01", "label": "PHISHING", "desc": "Anchor mismatch + Credential Lure",
     "data": create_mock_parsed_email(dmarc="PASS", anchor_mismatch=True, body_text="verify your credentials")},
    {"id": "P02", "label": "PHISHING", "desc": "DMARC Fail + Executable attachment",
     "data": create_mock_parsed_email(dmarc="FAIL", has_exe_att=True)},
    {"id": "P03", "label": "PHISHING", "desc": "Credential lure + HTML attachment",
     "data": create_mock_parsed_email(dmarc="PASS", body_text="login to update billing", has_html_att=True)},
    {"id": "P04", "label": "PHISHING", "desc": "Anchor mismatch + Urgent language",
     "data": create_mock_parsed_email(dmarc="PASS", anchor_mismatch=True, body_text="immediate action required")},
    {"id": "P05", "label": "PHISHING", "desc": "SPF Fail + DKIM Fail (DMARC unknown) + Executable",
     "data": create_mock_parsed_email(spf="FAIL", dkim="FAIL", dmarc="UNKNOWN", has_exe_att=True)},
    {"id": "P06", "label": "PHISHING", "desc": "Reply-To Mismatch + Executable attachment",
     "data": create_mock_parsed_email(dmarc="PASS", reply_mismatch=True, has_exe_att=True)},
    {"id": "P07", "label": "PHISHING", "desc": "Executable attachment + Urgent language",
     "data": create_mock_parsed_email(dmarc="PASS", has_exe_att=True, body_text="urgent invoice")},
    {"id": "P08", "label": "PHISHING", "desc": "HTML attachment + Credential lure + IP URL",
     "data": create_mock_parsed_email(dmarc="PASS", has_html_att=True, body_text="verify account", urls=["http://192.168.1.100/auth"])},
    {"id": "P09", "label": "PHISHING", "desc": "Anchor mismatch + DMARC fail",
     "data": create_mock_parsed_email(dmarc="FAIL", anchor_mismatch=True)},
    {"id": "P10", "label": "PHISHING", "desc": "Credential lure + Executable attachment",
     "data": create_mock_parsed_email(dmarc="PASS", body_text="verify your identity", has_exe_att=True)},

    # --- BENIGN CASES (Expected: NO_STRONG_INDICATORS_DETECTED) ---
    {"id": "B01", "label": "BENIGN", "desc": "Perfect auth, no indicators",
     "data": create_mock_parsed_email(spf="PASS", dkim="PASS", dmarc="PASS")},
    {"id": "B02", "label": "BENIGN", "desc": "SPF Fail, DMARC Pass (Forwarded)",
     "data": create_mock_parsed_email(spf="FAIL", dkim="PASS", dmarc="PASS")},
    {"id": "B03", "label": "BENIGN", "desc": "Legitimate newsletter (Return-Path mismatch)",
     "data": create_mock_parsed_email(dmarc="PASS", return_mismatch=True)},
    {"id": "B04", "label": "BENIGN", "desc": "Password reset (Credential lure, DMARC pass)",
     "data": create_mock_parsed_email(dmarc="PASS", body_text="click here to reset your password")},
    {"id": "B05", "label": "BENIGN", "desc": "Urgent email (Urgent language, DMARC pass)",
     "data": create_mock_parsed_email(dmarc="PASS", body_text="Please review this urgent report.")},
    {"id": "B06", "label": "BENIGN", "desc": "HTML attachment (no urgency, DMARC pass)",
     "data": create_mock_parsed_email(dmarc="PASS", has_html_att=True)},
    {"id": "B07", "label": "BENIGN", "desc": "Deep subdomain (AWS link, DMARC pass)",
     "data": create_mock_parsed_email(dmarc="PASS", urls=["https://us-east-1.console.aws.amazon.com/login"])},
    {"id": "B08", "label": "BENIGN", "desc": "Reply-To mismatch, DMARC pass (Support ticket)",
     "data": create_mock_parsed_email(dmarc="PASS", reply_mismatch=True)},
    {"id": "B09", "label": "BENIGN", "desc": "Missing DMARC but SPF/DKIM Pass",
     "data": create_mock_parsed_email(spf="PASS", dkim="PASS", dmarc="UNKNOWN")},
    {"id": "B10", "label": "BENIGN", "desc": "Newsletter + HTML attachment",
     "data": create_mock_parsed_email(dmarc="PASS", return_mismatch=True, has_html_att=True)},
    {"id": "B11", "label": "BENIGN", "desc": "SPF SoftFail equivalent handled as Pass (For simplicity SPF PASS in mock, but varying text)",
     "data": create_mock_parsed_email(dmarc="PASS", body_text="Hello team")},
    {"id": "B12", "label": "BENIGN", "desc": "Password reset + HTML attachment (Proofpoint safe)",
     "data": create_mock_parsed_email(dmarc="PASS", has_html_att=True, html_filename="SecureMessageAtt.html", body_text="verify identity")}, # Note: this will score 30 and be SUSPICIOUS without context.

    # --- AMBIGUOUS CASES (Expected: INCONCLUSIVE) ---
    {"id": "A01", "label": "AMBIGUOUS", "desc": "No auth headers, no indicators",
     "data": create_mock_parsed_email(spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN")},
    {"id": "A02", "label": "AMBIGUOUS", "desc": "No auth headers, Return-Path mismatch",
     "data": create_mock_parsed_email(spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN", return_mismatch=True)},
    {"id": "A03", "label": "AMBIGUOUS", "desc": "No auth headers, HTML attachment (Low score)",
     "data": create_mock_parsed_email(spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN", has_html_att=True)},
    {"id": "A04", "label": "AMBIGUOUS", "desc": "No auth headers, deep subdomain",
     "data": create_mock_parsed_email(spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN", urls=["https://us-east.aws.com"])},
    {"id": "A05", "label": "AMBIGUOUS", "desc": "No auth headers, Reply-To mismatch",
     "data": create_mock_parsed_email(spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN", reply_mismatch=True)},
    {"id": "A06", "label": "AMBIGUOUS", "desc": "No auth headers, password reset lure",
     "data": create_mock_parsed_email(spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN", body_text="reset your password")},
    {"id": "A07", "label": "AMBIGUOUS", "desc": "No auth headers, urgent language",
     "data": create_mock_parsed_email(spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN", body_text="urgent attention")},
    {"id": "A08", "label": "AMBIGUOUS", "desc": "No auth headers, ambiguous URL",
     "data": create_mock_parsed_email(spf="UNKNOWN", dkim="UNKNOWN", dmarc="UNKNOWN", urls=["http://example.com@login.com"])} # Wait, IP URL scores 20. 20 < 25, so INCONCLUSIVE.
]

def run_evaluation():
    classifier = EvidenceClassifier()
    detector = PhishingDetector()
    
    total = len(DATASET)
    correct = 0
    incorrect = 0
    
    # Phishing Metrics
    tp = 0 # True Positive (Label: PHISHING, Pred: PHISHING)
    fp = 0 # False Positive (Label: BENIGN/AMBIGUOUS, Pred: PHISHING)
    fn = 0 # False Negative (Label: PHISHING, Pred: BENIGN/AMBIGUOUS)
    tn = 0 # True Negative (Label: BENIGN, Pred: BENIGN/AMBIGUOUS - typically evaluated as strictly correct benign)

    misclassified = []

    print(f"--- EviPhish Phishing Detector Evaluation ---")
    print(f"Total cases: {total}")
    print("-" * 50)

    for case in DATASET:
        evidence = classifier.classify_findings(case["data"])
        result = detector.detect(case["data"], evidence)
        
        verdict = result["verdict"]
        label = case["label"]
        
        # Determine Prediction Category
        if verdict in ("LIKELY_PHISHING", "SUSPICIOUS"):
            pred = "PHISHING"
        elif verdict == "NO_STRONG_INDICATORS_DETECTED":
            pred = "BENIGN"
        elif verdict == "INCONCLUSIVE":
            pred = "AMBIGUOUS"
        else:
            pred = "UNKNOWN"

        is_correct = (pred == label)
        
        if is_correct:
            correct += 1
            if label == "PHISHING":
                tp += 1
            elif label == "BENIGN":
                tn += 1
        else:
            incorrect += 1
            misclassified.append({
                "id": case["id"],
                "desc": case["desc"],
                "label": label,
                "pred": pred,
                "verdict": verdict,
                "score": result["score"]
            })
            
            if pred == "PHISHING":
                fp += 1
            if label == "PHISHING" and pred != "PHISHING":
                fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print(f"Correct: {correct}")
    print(f"Incorrect: {incorrect}")
    print(f"Accuracy (Exact Match): {correct/total*100:.1f}%")
    print("-" * 50)
    
    print(f"PHISHING Class Metrics:")
    print(f"  True Positives: {tp}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall:    {recall:.3f}")
    print(f"  F1 Score:  {f1:.3f}")
    print("-" * 50)
    
    print("Confusion Matrix (Label \\ Prediction):")
    
    # We will build a small matrix for BENIGN, PHISHING, AMBIGUOUS
    matrix = { "BENIGN": {"BENIGN":0, "PHISHING":0, "AMBIGUOUS":0},
               "PHISHING": {"BENIGN":0, "PHISHING":0, "AMBIGUOUS":0},
               "AMBIGUOUS": {"BENIGN":0, "PHISHING":0, "AMBIGUOUS":0} }
               
    for case in DATASET:
        # Re-run quickly to populate matrix
        evidence = classifier.classify_findings(case["data"])
        res = detector.detect(case["data"], evidence)
        v = res["verdict"]
        p = "PHISHING" if v in ("LIKELY_PHISHING", "SUSPICIOUS") else "BENIGN" if v == "NO_STRONG_INDICATORS_DETECTED" else "AMBIGUOUS"
        matrix[case["label"]][p] += 1
        
    print("               | Pred BENIGN | Pred PHISH | Pred AMBIGUOUS")
    print(f"True BENIGN    | {matrix['BENIGN']['BENIGN']:<11} | {matrix['BENIGN']['PHISHING']:<10} | {matrix['BENIGN']['AMBIGUOUS']}")
    print(f"True PHISHING  | {matrix['PHISHING']['BENIGN']:<11} | {matrix['PHISHING']['PHISHING']:<10} | {matrix['PHISHING']['AMBIGUOUS']}")
    print(f"True AMBIGUOUS | {matrix['AMBIGUOUS']['BENIGN']:<11} | {matrix['AMBIGUOUS']['PHISHING']:<10} | {matrix['AMBIGUOUS']['AMBIGUOUS']}")
    print("-" * 50)

    if misclassified:
        print("Misclassified Cases:")
        for m in misclassified:
            print(f"  [{m['id']}] {m['desc']}")
            print(f"       Label: {m['label']} | Predicted: {m['pred']} ({m['verdict']}, Score: {m['score']})")

if __name__ == "__main__":
    run_evaluation()
