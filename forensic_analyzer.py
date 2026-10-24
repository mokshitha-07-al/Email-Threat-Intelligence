import re
from email import policy
from email.parser import BytesParser


def analyze_headers(file_path):

    with open(file_path, "rb") as file:
        email_message = BytesParser(policy=policy.default).parse(file)

    sender = email_message.get("From", "Not available")
    reply_to = email_message.get("Reply-To", "Not available")
    return_path = email_message.get("Return-Path", "Not available")
    message_id = email_message.get("Message-ID", "Not available")

    # Check Reply-To mismatch
    reply_to_mismatch = False

    if reply_to != "Not available" and sender != "Not available":
        sender_email = re.findall(r'[\w\.-]+@[\w\.-]+', sender)
        reply_email = re.findall(r'[\w\.-]+@[\w\.-]+', reply_to)

        if sender_email and reply_email:
            if sender_email[0].lower() != reply_email[0].lower():
                reply_to_mismatch = True

    # Extract Received headers
    received_headers = email_message.get_all("Received", [])

    sender_ip = "Not available"

    for header in received_headers:

        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            header
        )

        if ip_match:
            sender_ip = ip_match.group()
            break

    # Authentication information
    authentication_results = email_message.get(
        "Authentication-Results",
        "Not available"
    )

    received_spf = email_message.get(
        "Received-SPF",
        "Not available"
    )

    dkim_signature = email_message.get(
        "DKIM-Signature",
        "Not available"
    )

    # Attachment detection
    attachments = []
    suspicious_attachments = []

    dangerous_extensions = [
        ".exe",
        ".bat",
        ".cmd",
        ".scr",
        ".js",
        ".vbs",
        ".ps1"
    ]

    for part in email_message.walk():

        filename = part.get_filename()

        if filename:

            attachments.append(filename)

            filename_lower = filename.lower()

            for extension in dangerous_extensions:

                if filename_lower.endswith(extension):
                    suspicious_attachments.append(filename)
                    break

    return {
        "sender": sender,
        "reply_to": reply_to,
        "return_path": return_path,
        "message_id": message_id,
        "reply_to_mismatch": reply_to_mismatch,
        "sender_ip": sender_ip,
        "received_headers": received_headers,
        "authentication_results": authentication_results,
        "received_spf": received_spf,
        "dkim_signature": dkim_signature,
        "attachments": attachments,
        "suspicious_attachments": suspicious_attachments
    }