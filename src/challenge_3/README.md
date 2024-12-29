# Network Vulnerability Classification

This project fine-tunes a BERT model to classify network traffic as either normal or malicious.

## Project Structure
```
GenAI_CyberSecurity/
└── src/
    └── challenge_3/
        ├── network_vulnerability_dataset (1).csv
        ├── requirements.txt
        └── src/
            ├── network_vulnerability_classifier.py
            └── upload_to_huggingface.py
```

## Components

### 1. Model Training (`network_vulnerability_classifier.py`)
- Loads and preprocesses network traffic data
- Fine-tunes BERT for binary classification
- Uses Weights & Biases for tracking metrics
- Implements:
  - Data tokenization
  - Model training configuration
  - Performance metrics computation
  - Training progress monitoring

### 2. Model Upload (`upload_to_huggingface.py`)
- Handles model upload to Hugging Face Hub
- Securely manages authentication
- Automatically selects best checkpoint
- Uploads both model and tokenizer

## Key Features
- Binary classification (normal/malicious traffic)
- BERT-based architecture
- Achieved 94.65% accuracy
- Wandb integration for metrics tracking
- Secure token handling

## Setup and Usage

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Train the model:
```bash
python src/network_vulnerability_classifier.py
```

3. Upload to Hugging Face Hub:
```bash
python src/upload_to_huggingface.py
```

## Requirements
- Python 3.8+
- Hugging Face account with write access token
- Weights & Biases account (optional)
- GPU recommended for training

## Performance Metrics
- Accuracy: 94.65%
- Training Time: ~16 minutes
- Final Loss: 0.209

## Notes
- Model checkpoints saved in ./results
- Logs available in ./logs
- Requires dataset in parent directory 