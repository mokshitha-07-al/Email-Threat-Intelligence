
import streamlit as st
import tempfile
import os

from email_parser import parse_email
from ml_detector import detect_threat
from threat_detector import detect_rules
from forensic_analyzer import analyze_headers
from risk_engine import calculate_risk


st.set_page_config(
    page_title="AI Email Threat Detection",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ AI-Based Email Threat Detection")
st.write(
    "Upload an email file (.eml) to detect suspicious content, "
    "analyze email headers, and calculate its threat risk."
)

st.info("Upload an .eml file below to begin the security analysis.")

uploaded_file = st.file_uploader(
    "Choose an email file",
    type=["eml"]
)

if uploaded_file is not None:
    st.success(f"Selected file: {uploaded_file.name}")

    if st.button("🔍 Analyze Email", type="primary"):
        temp_path = None

        try:
            with tempfile.NamedTemporaryFile(
                delete=False,
                suffix=".eml"
            ) as temp_file:
                temp_file.write(uploaded_file.getvalue())
                temp_path = temp_file.name

            with st.spinner("Analyzing email security..."):
                email = parse_email(temp_path)
                ml_result = detect_threat(temp_path)
                rule_result = detect_rules(email["body"])
                forensic_result = analyze_headers(temp_path)

                ml_probability = (
                    ml_result["class_1_probability"] / 100
                )

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

            st.divider()
            st.header("📊 Email Security Report")

            st.subheader("📧 Email Information")

            col1, col2 = st.columns(2)

            with col1:
                st.write("**Sender:**", email["sender"])
                st.write("**Receiver:**", email["receiver"])

            with col2:
                st.write("**Subject:**", email["subject"])
                st.write("**Date:**", email["date"])

            st.divider()
            st.subheader("🚨 Threat Assessment")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric(
                    "Risk Score",
                    f"{risk_result['total_score']:.2f}/100"
                )

            with col2:
                st.metric(
                    "Threat Level",
                    risk_result["threat_level"]
                )

            with col3:
                st.metric(
                    "ML Suspicious-Class Probability",
                    f"{ml_result['class_1_probability']:.2f}%"
                )

            st.progress(
                min(
                    max(risk_result["total_score"] / 100, 0.0),
                    1.0
                )
            )

            if risk_result["threat_level"] == "HIGH":
                st.error(
                    "⚠️ " + risk_result["classification"]
                )
            elif risk_result["threat_level"] == "MEDIUM":
                st.warning(
                    "⚠️ " + risk_result["classification"]
                )
            else:
                st.success(
                    "✅ " + risk_result["classification"]
                )

            st.caption(
                "The ML probability is the model's estimated probability "
                "for class 1 (suspicious/spam-like email), not a guarantee "
                "that the email is phishing."
            )

            st.divider()
            left, right = st.columns(2)

            with left:
                st.subheader("🔍 Rule-Based Findings")

                st.write("**Suspicious words**")
                st.write(rule_result["suspicious_words"] or "None detected")

                st.write("**Urgency phrases**")
                st.write(rule_result["urgency_phrases"] or "None detected")

                st.write("**URLs found**")
                st.write(rule_result["urls"] or "None found")

                st.write("**Suspicious URLs**")
                st.write(
                    rule_result["suspicious_urls"] or "None detected"
                )

            with right:
                st.subheader("🕵️ Forensic Analysis")

                st.write("**Reply-To:**", forensic_result["reply_to"])
                st.write("**Return-Path:**", forensic_result["return_path"])
                st.write("**Message-ID:**", forensic_result["message_id"])
                st.write("**IP in Received headers:**",
                         forensic_result["sender_ip"])
                st.write("**Reply-To mismatch:**",
                         "Yes" if forensic_result["reply_to_mismatch"]
                         else "No / not detected")

                st.write(
                    "**Authentication Results:**",
                    forensic_result["authentication_results"]
                )

                st.write(
                    "**Received-SPF:**",
                    forensic_result["received_spf"]
                )

                st.write(
                    "**Attachments:**",
                    forensic_result["attachments"] or "None detected"
                )

                st.write(
                    "**Suspicious attachments:**",
                    forensic_result["suspicious_attachments"]
                    or "None detected"
                )

            st.divider()
            st.subheader("📈 Risk Score Breakdown")

            score_items = {
                "Machine Learning": risk_result["ml_score"],
                "Suspicious URL": risk_result["url_score"],
                "Urgency": risk_result["urgency_score"],
                "Suspicious Words": risk_result["word_score"],
                "Reply-To Mismatch": risk_result["reply_score"],
                "Suspicious Attachment": risk_result["attachment_score"]
            }

            st.bar_chart(score_items)

            st.write("**Individual risk contributions**")
            for name, score in score_items.items():
                st.write(f"- {name}: {score:.2f} points")

            with st.expander("View email body"):
                st.text(email["body"] or "No plain-text body found.")

            st.caption(
                "This is a prototype security analysis. "
                "A low score does not guarantee that an email is safe. "
                "Header information and authentication results may be "
                "missing from the uploaded email."
            )

        except Exception as error:
            st.error(f"Could not analyze this email: {error}")
            st.info(
                "Check that the .eml file is valid and the model files "
                "and Python modules are present in your project folder."
            )

        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

st.divider()
st.caption("AI Email Threat Detection and Forensic Analysis System")
