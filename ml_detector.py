import pickle
from email_parser import parse_email


# Load the trained ML model
with open("email_threat_model.pkl", "rb") as file:
    model = pickle.load(file)

# Load the TF-IDF vectorizer
with open("email_tfidf_vectorizer.pkl", "rb") as file:
    tfidf = pickle.load(file)


def detect_threat(file_path):

    # Read the email
    email = parse_email(file_path)

    # Get email body
    email_body = email["body"]

    # Convert email text into TF-IDF features
    email_tfidf = tfidf.transform([email_body])

    # Predict class
    prediction = model.predict(email_tfidf)[0]

    # Get probabilities
    probabilities = model.predict_proba(email_tfidf)[0]

    class_0_probability = probabilities[0] * 100
    class_1_probability = probabilities[1] * 100

    if prediction == 1:
        result = "SUSPICIOUS EMAIL"
    else:
        result = "LIKELY LEGITIMATE EMAIL"

    return {
        "prediction": prediction,
        "class_0_probability": class_0_probability,
        "class_1_probability": class_1_probability,
        "result": result
    }


if __name__ == "__main__":

    result = detect_threat("sample.eml")

    print("\n===================================")
    print("       ML EMAIL THREAT DETECTION")
    print("===================================")

    print("Predicted Class :", result["prediction"])
    print(f"Class 0 Probability : {result['class_0_probability']:.2f}%")
    print(f"Class 1 Probability : {result['class_1_probability']:.2f}%")
    print("Result :", result["result"])

    print("===================================")