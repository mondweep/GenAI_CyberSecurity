# Network Vulnerability Classification Model

## Model Details

### Model Description
- **Developed by:** thisismon
- **Model type:** Fine-tuned BERT (bert-base-uncased)
- **Language:** English
- **License:** MIT
- **Finetuned from model:** bert-base-uncased

## Uses

### Direct Use
This model is designed to classify network traffic logs as either normal or malicious. It can be used for:
- Network security monitoring
- Threat detection
- Traffic analysis

### Out-of-Scope Use
- Not intended for production deployment without additional testing
- Not suitable for non-English network logs
- Not designed for real-time traffic analysis

## Training Details

### Training Data
- Binary classification dataset of network traffic logs
- Split: 80% training, 20% validation
- Data format: Text descriptions of network events

### Training Procedure
- **Framework:** Hugging Face Transformers
- **Epochs:** 3
- **Batch size:** 16
- **Warmup steps:** 500
- **Weight decay:** 0.01
- **Training time:** 976.08 seconds

### Training Results
- **Accuracy:** 94.65%
- **Final Loss:** 0.209
- **Training metrics tracked with:** Weights & Biases

## How to Get Started with the Model

```python
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Load model and tokenizer
model = AutoModelForSequenceClassification.from_pretrained("thisismon/network-vulnerability-classifier")
tokenizer = AutoTokenizer.from_pretrained("thisismon/network-vulnerability-classifier")

# Example usage
text = "Unauthorized login attempt detected from IP 192.168.1.100"
inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=128)
outputs = model(**inputs)
prediction = outputs.logits.argmax(-1).item()
print("Malicious" if prediction == 1 else "Normal")
```

## Environmental Impact
- **Hardware Type:** GPU
- **Hours used:** ~0.27 (16 minutes)
- **Cloud Provider:** Local
- **Carbon Emitted:** Minimal (local training)

## Technical Specifications

### Model Architecture
- Base model: BERT (bert-base-uncased)
- Added classification head for binary classification
- Input max length: 128 tokens
- Output: Binary classification (0: Normal, 1: Malicious)

### Compute Infrastructure
- Python 3.8+
- PyTorch
- Transformers library
- GPU recommended for training 