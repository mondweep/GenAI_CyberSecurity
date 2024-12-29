from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

def load_model():
    # Load model and tokenizer from Hugging Face Hub
    model_name = "thisismon/network-vulnerability-classifier"
    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForSequenceClassification.from_pretrained(model_name)
    return model, tokenizer

def classify_traffic(model, tokenizer, text):
    # Prepare the input
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=128)
    
    # Get prediction
    with torch.no_grad():
        outputs = model(**inputs)
        prediction = outputs.logits.argmax(-1).item()
    
    # Return result
    return "Malicious" if prediction == 1 else "Normal"

def main():
    # Load model
    print("Loading model...")
    model, tokenizer = load_model()
    
    # Test cases
    test_cases = [
        "Multiple failed login attempts from IP 192.168.1.100",
        "Normal HTTP GET request to /index.html",
        "SQL injection attempt detected in form submission",
        "User successfully logged in from known IP address",
        "Port scanning activity detected from external IP",
    ]
    
    # Run predictions
    print("\nTesting network traffic patterns:")
    print("-" * 50)
    for traffic in test_cases:
        result = classify_traffic(model, tokenizer, traffic)
        print(f"\nTraffic: {traffic}")
        print(f"Classification: {result}")
    
    # Interactive testing
    print("\n\nEnter your own network traffic patterns (type 'quit' to exit):")
    while True:
        user_input = input("\nEnter traffic pattern: ")
        if user_input.lower() == 'quit':
            break
        result = classify_traffic(model, tokenizer, user_input)
        print(f"Classification: {result}")

if __name__ == "__main__":
    main() 