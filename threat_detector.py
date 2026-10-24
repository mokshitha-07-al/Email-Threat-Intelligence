import re


def detect_rules(email_body):

    suspicious_words = [
        "urgent",
        "verify",
        "password",
        "account",
        "click",
        "security",
        "winner",
        "prize",
        "suspended",
        "blocked"
    ]

    urgency_phrases = [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "account will be closed",
        "account will be blocked"
    ]

    suspicious_url_words = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "confirm"
    ]

    text = email_body.lower()

    found_words = []

    for word in suspicious_words:
        if word in text:
            found_words.append(word)

    found_urgency = []

    for phrase in urgency_phrases:
        if phrase in text:
            found_urgency.append(phrase)

    urls = re.findall(r"https?://[^\s]+", email_body)

    suspicious_urls = []

    for url in urls:

        url_lower = url.lower()

        for word in suspicious_url_words:

            if word in url_lower:
                suspicious_urls.append(url)
                break

    return {
        "suspicious_words": found_words,
        "urgency_phrases": found_urgency,
        "urls": urls,
        "suspicious_urls": suspicious_urls
    }