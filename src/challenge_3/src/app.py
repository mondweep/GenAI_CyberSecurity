from flask import Flask, render_template, request, jsonify
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

app = Flask(__name__)

# Load model and tokenizer globally
print("Loading model...")
MODEL_NAME = "thisismon/network-vulnerability-classifier"
tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
print("Model loaded successfully!")

# Keep track of classifications
normal_count = 0
malicious_count = 0

@app.route('/')
def home():
    return render_template('index.html', 
                         normal_count=normal_count, 
                         malicious_count=malicious_count)

@app.route('/analyze', methods=['POST'])
def analyze():
    global normal_count, malicious_count
    
    # Get the traffic pattern from the request
    traffic_pattern = request.json.get('traffic_pattern', '')
    
    # Tokenize and predict
    inputs = tokenizer(traffic_pattern, return_tensors="pt", truncation=True, max_length=128)
    with torch.no_grad():
        outputs = model(**inputs)
        prediction = outputs.logits.argmax(-1).item()
    
    # Update counters
    if prediction == 0:
        normal_count += 1
        result = "Normal"
    else:
        malicious_count += 1
        result = "Malicious"
    
    # Return result
    return jsonify({
        'result': result,
        'normal_count': normal_count,
        'malicious_count': malicious_count
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000) 