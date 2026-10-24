def calculate_risk(
    ml_probability,
    suspicious_urls,
    urgency_phrases,
    suspicious_words,
    reply_to_mismatch=False,
    suspicious_attachment=False
):

    # ML score: maximum 40
    ml_score = ml_probability * 40

    # URL score
    url_score = 20 if suspicious_urls else 0

    # Urgency score
    urgency_score = 15 if urgency_phrases else 0

    # Suspicious word score
    word_score = 10 if suspicious_words else 0

    # Reply-To mismatch score
    reply_score = 10 if reply_to_mismatch else 0

    # Attachment score
    attachment_score = 5 if suspicious_attachment else 0

    # Final score
    total_score = (
        ml_score
        + url_score
        + urgency_score
        + word_score
        + reply_score
        + attachment_score
    )

    # Make sure score does not exceed 100
    total_score = min(total_score, 100)

    # Determine threat level
    if total_score >= 75:
        threat_level = "HIGH"

    elif total_score >= 40:
        threat_level = "MEDIUM"

    else:
        threat_level = "LOW"

    # Determine final classification
    if ml_probability >= 0.5:

        if threat_level == "HIGH":
            classification = "SUSPECTED PHISHING"
        else:
            classification = "POSSIBLE PHISHING"

    else:
        classification = "LIKELY LEGITIMATE"

    return {
        "ml_score": ml_score,
        "url_score": url_score,
        "urgency_score": urgency_score,
        "word_score": word_score,
        "reply_score": reply_score,
        "attachment_score": attachment_score,
        "total_score": total_score,
        "threat_level": threat_level,
        "classification": classification
    }


# Test the risk engine
if __name__ == "__main__":

    result = calculate_risk(
        ml_probability=0.9959,
        suspicious_urls=["http://example.com/login"],
        urgency_phrases=["urgent", "immediately"],
        suspicious_words=[
            "urgent",
            "verify",
            "account",
            "suspended"
        ]
    )

    print("\n===================================")
    print("          RISK ANALYSIS")
    print("===================================")

    print(f"ML Score          : {result['ml_score']:.2f}/40")
    print(f"URL Score         : {result['url_score']}/20")
    print(f"Urgency Score     : {result['urgency_score']}/15")
    print(f"Suspicious Words  : {result['word_score']}/10")
    print(f"Reply-To Score    : {result['reply_score']}/10")
    print(f"Attachment Score  : {result['attachment_score']}/5")

    print("-----------------------------------")

    print(f"FINAL RISK SCORE  : {result['total_score']:.2f}/100")
    print(f"THREAT LEVEL      : {result['threat_level']}")
    print(f"CLASSIFICATION    : {result['classification']}")

    print("===================================")