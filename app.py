import streamlit as st
import pandas as pd
import joblib
import re
import tldextract
import numpy as np
from urllib.parse import urlparse

# Load trained model and scaler
model = joblib.load("phishing_model.pkl")
scaler = joblib.load("phishing_scaler.pkl")

# List of all features used by the model
feature_columns = ['length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at',
 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde',
 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma',
 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash',
 'http_in_path', 'https_token', 'ratio_digits_url', 'ratio_digits_host',
 'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
 'nb_subdomains', 'prefix_suffix', 'random_domain', 'shortening_service',
 'path_extension', 'nb_redirection', 'nb_external_redirection',
 'length_words_raw', 'char_repeat', 'shortest_words_raw', 'shortest_word_host',
 'shortest_word_path', 'longest_words_raw', 'longest_word_host',
 'longest_word_path', 'avg_words_raw', 'avg_word_host', 'avg_word_path',
 'phish_hints', 'domain_in_brand', 'brand_in_subdomain', 'brand_in_path',
 'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
 'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection',
 'ratio_intErrors', 'ratio_extErrors', 'login_form', 'external_favicon',
 'links_in_tags', 'submit_email', 'ratio_intMedia', 'ratio_extMedia', 'sfh',
 'iframe', 'popup_window', 'safe_anchor', 'onmouseover', 'right_clic',
 'empty_title', 'domain_in_title', 'domain_with_copyright',
 'whois_registered_domain', 'domain_registration_length', 'domain_age',
 'web_traffic', 'dns_record', 'google_index', 'page_rank']

# Feature extraction from a given URL (dummy for some features)
import re
import tldextract
from urllib.parse import urlparse

def extract_features_from_url(url):
    features = {}

    # Extract components
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.domain
    subdomain = ext.subdomain
    suffix = ext.suffix
    hostname = parsed.netloc
    path = parsed.path

    # Extractable features
    features['length_url'] = len(url)
    features['length_hostname'] = len(hostname)
    features['ip'] = 1 if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", hostname) else 0
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.lower().count('or')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')
    features['nb_www'] = url.lower().count('www')
    features['nb_com'] = url.lower().count('.com')
    features['nb_dslash'] = url.count('//')
    features['http_in_path'] = 1 if 'http' in path else 0
    features['https_token'] = 1 if 'https' in url.lower() else 0
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / max(len(url), 1)
    features['ratio_digits_host'] = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)
    features['punycode'] = 1 if 'xn--' in url else 0
    features['port'] = 1 if ':' in hostname and hostname.split(':')[-1].isdigit() else 0
    features['tld_in_path'] = 1 if suffix in path else 0
    features['tld_in_subdomain'] = 1 if suffix in subdomain else 0
    features['nb_subdomains'] = len(subdomain.split('.')) if subdomain else 0
    features['prefix_suffix'] = 1 if '-' in domain else 0
    features['shortening_service'] = 1 if re.search(r'(bit\.ly|goo\.gl|shorte\.st|tinyurl\.com|ow\.ly)', url.lower()) else 0

    # Fill the rest with 0 if they exist in model but not extracted
    for col in feature_columns:
        if col not in features:
            features[col] = 0

    return pd.DataFrame([features])[feature_columns]


# ---------------- Streamlit UI ---------------- #

st.set_page_config(page_title="Phishing Detection", layout="centered")
st.title("🛡️ Phishing Website Detection")
st.markdown("Detect whether a URL is **Legitimate** or **Phishing** using a Machine Learning model.")

mode = st.radio("Choose Input Method", ["🔗 Enter a URL", "📁 Upload CSV"])

if mode == "🔗 Enter a URL":
    url = st.text_input("Enter a URL here", value="https://example.com")
    if st.button("🔍 Analyze"):
        try:
            input_df = extract_features_from_url(url)
            scaled = scaler.transform(input_df)
            pred = model.predict(scaled)[0]
            proba = model.predict_proba(scaled)[0]

            if pred == 1:
                st.error(f"🚨 **Phishing Website Detected**")
            else:
                st.success(f"✅ **Legitimate Website**")

            st.info(f"📊 **Model Confidence:** {proba[1]*100:.2f}% Phishing | {proba[0]*100:.2f}% Legitimate")
            with st.expander("Show Extracted Features"):
                st.dataframe(input_df.T)

        except Exception as e:
            st.error(f"❌ Error: {e}")

else:
    file = st.file_uploader("Upload a CSV file with extracted features", type=["csv"])
    if file:
        try:
            df = pd.read_csv(file)
            if 'status' in df.columns:
                df.drop(columns=['status'], inplace=True)

            input_df = df[feature_columns]
            scaled = scaler.transform(input_df)
            predictions = model.predict(scaled)
            probs = model.predict_proba(scaled)

            df["Prediction"] = ["Phishing 🚨" if p == 1 else "Legitimate ✅" for p in predictions]
            df["Confidence_Phishing_%"] = [f"{prob[1]*100:.2f}" for prob in probs]

            st.success("✅ Prediction complete")
            st.dataframe(df)

            csv = df.to_csv(index=False).encode("utf-8")
            st.download_button("📥 Download Predictions", csv, file_name="phishing_predictions.csv", mime="text/csv")

        except Exception as e:
            st.error(f"❌ Error processing file: {e}")

st.markdown("---")
st.caption("🔒 Built with ❤️ by Aman | Powered by Scikit-learn & Streamlit")



