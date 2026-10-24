from email import policy
from email.parser import BytesParser


def parse_email(file_path):

    with open(file_path, "rb") as file:
        email_message = BytesParser(
            policy=policy.default
        ).parse(file)

    sender = email_message.get("From", "Not available")
    receiver = email_message.get("To", "Not available")
    subject = email_message.get("Subject", "Not available")
    date = email_message.get("Date", "Not available")

    body = ""

    if email_message.is_multipart():

        for part in email_message.walk():

            if part.get_content_type() == "text/plain":

                body = part.get_content()

                break

    else:

        body = email_message.get_content()

    return {
        "sender": sender,
        "receiver": receiver,
        "subject": subject,
        "date": date,
        "body": body
    }


if __name__ == "__main__":

    email = parse_email("sample.eml")

    print("\n===================================")
    print("         EMAIL PARSER TEST")
    print("===================================")

    print("Sender   :", email["sender"])
    print("Receiver :", email["receiver"])
    print("Subject  :", email["subject"])
    print("Date     :", email["date"])

    print("\nEmail Body:")
    print(email["body"])

    print("===================================")