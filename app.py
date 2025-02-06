from flask import Flask, request, jsonify
import pickle
import re
from urllib.parse import urlparse
from flask_cors import CORS


app = Flask(__name__)
CORS(app)  # Enables CORS for frontend-backend communication

# Load the trained model
with open('malicious_url_model.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

# Feature Engineering Functions
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)', url)
    return 1 if match else 0

def abnormal_url(url):
    hostname = urlparse(url).hostname
    return 1 if re.search(str(hostname), url) else 0

def count_dot(url):
    return url.count('.')

def count_www(url):
    return url.count('www')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
    return urlparse(url).path.count('/')

def no_of_embed(url):
    return urlparse(url).path.count('//')

def shortening_service(url):
    match = re.search(r'bit\.ly|goo\.gl|shorte\.st|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs', url)
    return 1 if match else 0

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(url)

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search('PayPal|login|signin|bank|account|update|free|bonus|ebayisapi|webscr', url)
    return 1 if match else 0

def digit_count(url):
    return sum(c.isdigit() for c in url)

def letter_count(url):
    return sum(c.isalpha() for c in url)

def fd_length(url):
    try:
        return len(urlparse(url).path.split('/')[1])
    except:
        return 0

def tld_length(url):
    return len(url)

@app.route('/')
def home():
    return jsonify({"message": "Malicious URL Detection API is running!"})

@app.route('/api/predict', methods=['POST'])
def api_predict():
    try:
        data = request.json
        url = data.get("url", "")

        # Feature Extraction
        features = [
            having_ip_address(url),
            abnormal_url(url),
            count_dot(url),
            count_www(url),
            count_atrate(url),
            no_of_dir(url),
            no_of_embed(url),
            shortening_service(url),
            count_https(url),
            count_http(url),
            count_per(url),
            count_ques(url),
            count_hyphen(url),
            count_equal(url),
            url_length(url),
            hostname_length(url),
            suspicious_words(url),
            digit_count(url),
            letter_count(url),
            fd_length(url),
            tld_length(url)
        ]
        features = [features]  # Convert to 2D array for prediction

        # Make Prediction
        prediction = model.predict(features)
        result = 'Safe' if prediction[0] == 0 else 'Malicious'

        return jsonify({'url': url, 'prediction': result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

import os
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Use Render's assigned port
    app.run(host="0.0.0.0", port=port)
