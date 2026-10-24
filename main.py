from email_parser import parse_email
from ml_detector import detect_threat
from threat_detector import detect_rules
from forensic_analyzer import analyze_headers
from risk_engine import calculate_risk


# ==========================================
# FILE TO ANALYZE
# ==========================================

file_path = "sample.eml"


# ==========================================
# 1. EMAIL PARSING
# ==========================================

email = parse_email(file_path)


# ==========================================
# 2. ML THREAT DETECTION
# ==========================================

ml_result = detect_threat(file_path)

ml_probability = ml_result["class_1_probability"] / 100


# ==========================================
# 3. RULE-BASED DETECTION
# ==========================================

rule_result = detect_rules(email["body"])


# ==========================================
# 4. FORENSIC ANALYSIS
# ==========================================

forensic_result = analyze_headers(file_path)


# ==========================================
# 5. RISK CALCULATION
# ==========================================

risk_result = calculate_risk(
    ml_probability=ml_probability,
    suspicious_urls=rule_result["suspicious_urls"],
    urgency_phrases=rule_result["urgency_phrases"],
    suspicious_words=rule_result["suspicious_words"],
    reply_to_mismatch=forensic_result["reply_to_mismatch"],
    suspicious_attachment=bool(
        forensic_result["suspicious_attachments"]
    )
)


# ==========================================
# COMPLETE SECURITY REPORT
# ==========================================

print("\n")
print("============================================")
print("       COMPLETE EMAIL SECURITY ANALYSIS")
print("============================================")


# ==========================================
# EMAIL INFORMATION
# ==========================================

print("\nEMAIL INFORMATION")
print("--------------------------------------------")

print("Sender   :", email["sender"])
print("Receiver :", email["receiver"])
print("Subject  :", email["subject"])
print("Date     :", email["date"])


# ==========================================
# ML DETECTION
# ==========================================

print("\nML DETECTION")
print("--------------------------------------------")

print(
    f"Class 0 Probability : "
    f"{ml_result['class_0_probability']:.2f}%"
)

print(
    f"Class 1 Probability : "
    f"{ml_result['class_1_probability']:.2f}%"
)

print(
    "Predicted Class :",
    ml_result["prediction"]
)


# ==========================================
# RULE-BASED FINDINGS
# ==========================================

print("\nRULE-BASED FINDINGS")
print("--------------------------------------------")

print(
    "Suspicious Words :",
    rule_result["suspicious_words"]
)

print(
    "Urgency Phrases  :",
    rule_result["urgency_phrases"]
)

print(
    "URLs             :",
    rule_result["urls"]
)

print(
    "Suspicious URLs  :",
    rule_result["suspicious_urls"]
)


# ==========================================
# FORENSIC ANALYSIS
# ==========================================

print("\nFORENSIC ANALYSIS")
print("--------------------------------------------")

print(
    "Reply-To     :",
    forensic_result["reply_to"]
)

print(
    "Return-Path  :",
    forensic_result["return_path"]
)

print(
    "Message-ID   :",
    forensic_result["message_id"]
)

print(
    "Sender IP    :",
    forensic_result["sender_ip"]
)

print(
    "Authentication Results :",
    forensic_result["authentication_results"]
)

print(
    "Attachments :",
    forensic_result["attachments"]
)

print(
    "Suspicious Attachments :",
    forensic_result["suspicious_attachments"]
)

print(
    "Reply-To Mismatch :",
    forensic_result["reply_to_mismatch"]
)


# ==========================================
# RISK ANALYSIS
# ==========================================

print("\nRISK ANALYSIS")
print("--------------------------------------------")

print(
    f"ML Score          : "
    f"{risk_result['ml_score']:.2f}/40"
)

print(
    f"URL Score         : "
    f"{risk_result['url_score']}/20"
)

print(
    f"Urgency Score     : "
    f"{risk_result['urgency_score']}/15"
)

print(
    f"Suspicious Words  : "
    f"{risk_result['word_score']}/10"
)

print(
    f"Reply-To Score    : "
    f"{risk_result['reply_score']}/10"
)

print(
    f"Attachment Score  : "
    f"{risk_result['attachment_score']}/5"
)

print("--------------------------------------------")

print(
    f"FINAL RISK SCORE  : "
    f"{risk_result['total_score']:.2f}/100"
)

print(
    "THREAT LEVEL      :",
    risk_result["threat_level"]
)

print(
    "CLASSIFICATION    :",
    risk_result["classification"]
)

print("============================================")