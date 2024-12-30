import pandas as pd
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
from sklearn.model_selection import train_test_split
import torch
from datasets import Dataset
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
import random
from sklearn.model_selection import KFold
import string
import wandb
from transformers import EarlyStoppingCallback
import time
from sklearn.model_selection import StratifiedKFold

# Set device
device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
if torch.backends.mps.is_available():
    device = torch.device('mps')
print(f"Using device: {device}")

def clean_and_balance_dataset(file_path="../network_vulnerability_dataset (1).csv"):
    """Clean and balance the dataset with proper labeling and data augmentation."""
    print("Loading and cleaning dataset...")
    
    # Load original dataset
    df = pd.read_csv(file_path)
    original_size = len(df)
    print(f"Original dataset size: {original_size}")
    
    # Enhanced criteria for normal traffic (expanded)
    normal_patterns = [
        # Standard HTTP/HTTPS patterns
        "standard get request", "normal traffic", "regular user",
        "successfully logged in", "user viewing", "standard http",
        "http 200", "successful", "completed successfully",
        
        # Common legitimate operations
        "regular database", "standard select", "user accessing",
        "valid login", "authorized access", "regular file",
        "standard download", "normal accessing", "standard browsing",
        
        # Legitimate protocols
        "via http", "via https", "via sftp", "via ssh",
        
        # Legitimate resources
        "to dashboard", "to product catalog", "to database",
        "to webpage", "to file server"
    ]
    
    # Enhanced criteria for malicious traffic
    malicious_patterns = [
        # Clear attack indicators
        "injection attempt", "exploit attempt", "worm detected",
        "unauthorized access", "privilege escalation", "brute force",
        
        # Suspicious activities
        "multiple failed login", "port scanning", "data leak",
        "suspicious packet", "malicious script", "unauthorized software",
        
        # Known attack patterns
        "sql injection", "ddos", "arp spoofing",
        "dns tunneling", "reconnaissance"
    ]
    
    def determine_label(text):
        text_lower = text.lower()
        
        # Check for explicit normal patterns
        normal_match = any(pattern in text_lower for pattern in normal_patterns)
        malicious_match = any(pattern in text_lower for pattern in malicious_patterns)
        
        # More balanced logic
        if normal_match and not malicious_match:
            return 0
        elif malicious_match:
            return 1
        elif "error" in text_lower or "failed" in text_lower:
            # Only mark as malicious if it's a security-related failure
            return 1 if any(sec_term in text_lower for sec_term in ["login", "auth", "access", "security"]) else 0
        # Default to normal if uncertain (changed from previous malicious default)
        return 0
    
    # Relabel based on enhanced criteria
    print("Relabeling data based on improved criteria...")
    df['corrected_label'] = df['Text'].apply(determine_label)
    
    # Calculate required augmentation size
    current_normal = len(df[df['corrected_label'] == 0])
    current_malicious = len(df[df['corrected_label'] == 1])
    target_size = original_size // 2  # Equal split between normal and malicious
    
    # Data Augmentation for normal traffic
    normal_templates = [
        "User {} accessing {} via {}",
        "Standard {} request to {} completed successfully",
        "Normal {} traffic from {} to {}",
        "Successful {} operation on {}",
        "Regular {} activity on {} using {}",
        "Authorized user performing {} on {} through {}"
    ]
    
    resources = [
        "webpage", "database", "file server", "application",
        "product catalog", "user profile", "dashboard",
        "API endpoint", "web service", "content management system"
    ]
    
    actions = [
        "viewing", "accessing", "reading", "querying",
        "downloading", "browsing", "requesting",
        "monitoring", "updating", "retrieving"
    ]
    
    protocols = [
        "HTTP", "HTTPS", "SSH", "FTP", "SFTP",
        "TLS", "WebSocket", "API"
    ]
    
    # Generate augmented normal traffic data
    augmented_size = target_size - current_normal
    print(f"Generating {augmented_size} augmented normal traffic records...")
    
    augmented_data = []
    for _ in range(augmented_size):
        template = np.random.choice(normal_templates)
        if "{}" in template:
            text = template.format(
                np.random.choice(actions),
                np.random.choice(resources),
                np.random.choice(protocols)
            )
            augmented_data.append({"Text": text, "corrected_label": 0})
    
    # Add augmented data
    augmented_df = pd.DataFrame(augmented_data)
    df = pd.concat([df, augmented_df], ignore_index=True)
    
    # Final balance check
    normal_samples = df[df['corrected_label'] == 0]
    malicious_samples = df[df['corrected_label'] == 1]
    
    print(f"Final distribution:")
    print(f"Normal traffic: {len(normal_samples)}")
    print(f"Malicious traffic: {len(malicious_samples)}")
    
    # Save balanced dataset
    balanced_df = pd.concat([normal_samples, malicious_samples]).sample(frac=1, random_state=42).reset_index(drop=True)
    balanced_df.to_csv("../balanced_network_vulnerability_dataset.csv", index=False)
    
    return balanced_df

def tokenize_data(texts, labels, tokenizer):
    """Tokenize the input texts and prepare for training."""
    encodings = tokenizer(texts, truncation=True, padding=True)
    dataset = Dataset.from_dict({
        'input_ids': encodings['input_ids'],
        'attention_mask': encodings['attention_mask'],
        'labels': labels
    })
    return dataset

def compute_metrics(eval_pred):
    """Compute metrics for evaluation."""
    predictions, labels = eval_pred
    predictions = np.argmax(predictions, axis=1)
    
    accuracy = accuracy_score(labels, predictions)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, predictions, average='binary')
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
    }

def add_noise_to_text(text, noise_level=0.1):
    """Add controlled noise to text data.
    
    Args:
        text (str): Original text
        noise_level (float): Probability of applying each noise type (0.0 to 1.0)
    """
    if random.random() > noise_level:
        return text  # No noise added
        
    noise_types = random.choice([
        'typo',
        'swap_words',
        'add_whitespace',
        'change_case',
        'add_punctuation'
    ])
    
    words = text.split()
    
    if noise_types == 'typo':
        # Introduce common typos (if word length > 3)
        if len(words) > 0:
            word_idx = random.randint(0, len(words)-1)
            if len(words[word_idx]) > 3:
                char_idx = random.randint(0, len(words[word_idx])-1)
                word_chars = list(words[word_idx])
                # Either swap adjacent chars or replace with nearby keyboard char
                if random.random() < 0.5 and char_idx < len(word_chars)-1:
                    word_chars[char_idx], word_chars[char_idx+1] = word_chars[char_idx+1], word_chars[char_idx]
                else:
                    nearby_chars = 'qwertyuiop' if word_chars[char_idx] in 'qwertyuiop' else 'asdfghjkl' if word_chars[char_idx] in 'asdfghjkl' else 'zxcvbnm'
                    word_chars[char_idx] = random.choice(nearby_chars)
                words[word_idx] = ''.join(word_chars)
    
    elif noise_types == 'swap_words':
        # Swap adjacent words
        if len(words) > 1:
            idx = random.randint(0, len(words)-2)
            words[idx], words[idx+1] = words[idx+1], words[idx]
    
    elif noise_types == 'add_whitespace':
        # Add extra space
        if len(words) > 0:
            idx = random.randint(0, len(words)-1)
            words[idx] = words[idx] + ' '
    
    elif noise_types == 'change_case':
        # Randomly change case of a word
        if len(words) > 0:
            idx = random.randint(0, len(words)-1)
            words[idx] = words[idx].upper() if random.random() < 0.5 else words[idx].lower()
    
    elif noise_types == 'add_punctuation':
        # Add random punctuation
        if len(words) > 0:
            idx = random.randint(0, len(words)-1)
            words[idx] = words[idx] + random.choice('.,!?')
    
    return ' '.join(words)

def prepare_training_data(texts, labels):
    """Prepare training data with noise augmentation."""
    augmented_texts = []
    augmented_labels = []
    
    for text, label in zip(texts, labels):
        # Add original text
        augmented_texts.append(text)
        augmented_labels.append(label)
        
        # Add noisy version (only for normal traffic to help balance)
        if label == 0:  # Normal traffic
            noisy_text = add_noise_to_text(text)
            augmented_texts.append(noisy_text)
            augmented_labels.append(label)
    
    return augmented_texts, augmented_labels

def add_diverse_noise_to_text(text, noise_level=0.1):
    """Add diverse types of noise to text data."""
    if random.random() > noise_level:
        return text
        
    words = text.split()
    if len(words) < 2:
        return text
        
    noise_type = random.choice(['swap', 'typo', 'case', 'space'])
    
    if noise_type == 'swap' and len(words) > 2:
        idx = random.randint(0, len(words)-2)
        words[idx], words[idx+1] = words[idx+1], words[idx]
    elif noise_type == 'typo' and any(len(w) > 3 for w in words):
        idx = random.choice([i for i, w in enumerate(words) if len(w) > 3])
        char_idx = random.randint(0, len(words[idx])-1)
        chars = list(words[idx])
        chars[char_idx] = random.choice(string.ascii_lowercase)
        words[idx] = ''.join(chars)
    elif noise_type == 'case':
        idx = random.randint(0, len(words)-1)
        words[idx] = words[idx].upper()
    elif noise_type == 'space':
        idx = random.randint(0, len(words)-1)
        words[idx] = words[idx] + ' '
    
    return ' '.join(words)

def retrain_model():
    """Retrain the model with balanced dataset and cross-validation."""
    print("Starting model retraining process...")
    
    # Get balanced dataset
    balanced_df = clean_and_balance_dataset()
    
    # Convert to lists for k-fold
    texts = balanced_df['Text'].tolist()
    labels = balanced_df['corrected_label'].tolist()
    
    # Initialize tokenizer and model
    print("Initializing tokenizer and model...")
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
    model = AutoModelForSequenceClassification.from_pretrained(
        "bert-base-uncased",
        num_labels=2
    ).to(device)
    
    # Stricter training arguments with explanations
    training_args = TrainingArguments(
        output_dir="./balanced_model",
        num_train_epochs=3,
        per_device_train_batch_size=16,
        per_device_eval_batch_size=16,
        warmup_steps=500,
        weight_decay=0.1,
        logging_dir="./logs",
        evaluation_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="accuracy",
        learning_rate=2e-5,
        gradient_accumulation_steps=2,
        lr_scheduler_type="cosine",
        # Early stopping through checkpoints
        save_total_limit=2,  # Keep only the last 2 checkpoints
        greater_is_better=True  # For accuracy metric
    )
    
    # Use k-fold cross validation
    kf = KFold(n_splits=5, shuffle=True, random_state=42)
    
    fold_scores = []
    for fold, (train_idx, val_idx) in enumerate(kf.split(texts)):
        print(f"\nTraining fold {fold+1}/5...")
        
        # Get fold's train/val data
        fold_train_texts = [texts[i] for i in train_idx]
        fold_train_labels = [labels[i] for i in train_idx]
        fold_val_texts = [texts[i] for i in val_idx]
        fold_val_labels = [labels[i] for i in val_idx]
        
        # Add noise to training data
        fold_train_texts = [add_diverse_noise_to_text(text) for text in fold_train_texts]
        
        # Prepare datasets
        train_dataset = tokenize_data(fold_train_texts, fold_train_labels, tokenizer)
        val_dataset = tokenize_data(fold_val_texts, fold_val_labels, tokenizer)
        
        # Initialize trainer for this fold
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics
        )
        
        # Train and evaluate
        trainer.train()
        eval_results = trainer.evaluate()
        fold_scores.append(eval_results)
        
        print(f"\nFold {fold+1} Results:")
        print(eval_results)
    
    # Print average scores across folds
    print("\nAverage scores across folds:")
    metrics = ['eval_loss', 'eval_accuracy', 'eval_precision', 'eval_recall', 'eval_f1']
    for metric in metrics:
        avg_score = sum(score[metric] for score in fold_scores) / len(fold_scores)
        print(f"{metric}: {avg_score:.4f}")
    
    return model, tokenizer

def validate_model(model, tokenizer):
    """Validate the retrained model."""
    print("\nValidating model with diverse test cases...")
    
    # Move model to CPU for validation
    model = model.cpu()
    
    test_variations = [
        # Standard cases with variations
        ["User viewing product catalog", 
         "Customer browsing product listing",
         "Client accessing catalog page"],
        
        ["SQL injection attempt detected",
         "Suspicious database query pattern observed",
         "Potential SQL compromise attempt"],
        
        ["Multiple failed login attempts",
         "Repeated authentication failures",
         "Login failure threshold exceeded"],
    ]
    
    model.eval()
    with torch.no_grad():
        for test_group in test_variations:
            print("\nTesting variations:")
            for text in test_group:
                inputs = tokenizer(text, return_tensors="pt", truncation=True)
                # Move inputs to CPU
                inputs = {k: v.cpu() for k, v in inputs.items()}
                outputs = model(**inputs)
                prediction = outputs.logits.argmax(-1).item()
                confidence = torch.nn.functional.softmax(outputs.logits, dim=1)[0]
                print(f"\nText: {text}")
                print(f"Prediction: {'Normal' if prediction == 0 else 'Malicious'}")
                print(f"Confidence: {confidence[prediction].item():.2%}")

def train_with_wandb():
    """Training function with improved architecture and regularization"""
    # Initialize wandb with new config
    run = wandb.init(
        project="network-vulnerability-classifier",
        name=f"improved-arch-{time.strftime('%Y%m%d-%H%M%S')}",
        config={
            "architecture": "bert-base-uncased",
            "learning_rate": 5e-7,      # Much smaller learning rate
            "weight_decay": 0.8,        # Stronger regularization
            "num_train_epochs": 5,      # More epochs
            "warmup_ratio": 0.3,        # Longer warmup
            "gradient_clip": 0.3,       # Aggressive clipping
            "dropout": 0.5              # Maximum dropout
        }
    )
    config = wandb.config
    
    # Get balanced dataset
    balanced_df = clean_and_balance_dataset()
    
    # Calculate class weights
    total_samples = len(balanced_df)
    class_counts = balanced_df['corrected_label'].value_counts()
    class_weights = {
        0: total_samples / (2 * class_counts[0]),
        1: total_samples / (2 * class_counts[1])
    }
    print(f"Class weights: {class_weights}")
    
    # Initialize tokenizer
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
    
    # Initialize model with high dropout
    model = AutoModelForSequenceClassification.from_pretrained(
        "bert-base-uncased",
        num_labels=2,
        hidden_dropout_prob=config.dropout,
        attention_probs_dropout_prob=config.dropout,
        classifier_dropout=config.dropout  # Add dropout to classifier layer
    ).to(device)
    
    # Enhanced training arguments
    training_args = TrainingArguments(
        output_dir=f"./balanced_model_{run.id}",
        num_train_epochs=config.num_train_epochs,
        per_device_train_batch_size=8,   # Smaller batch size
        per_device_eval_batch_size=8,
        
        # Learning rate and regularization
        learning_rate=config.learning_rate,
        weight_decay=config.weight_decay,
        warmup_ratio=config.warmup_ratio,
        
        # Gradient handling
        gradient_accumulation_steps=32,   # Increased for stability
        max_grad_norm=config.gradient_clip,
        fp16=True,                       # Mixed precision training
        
        # Early stopping and evaluation
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        evaluation_strategy="steps",
        eval_steps=50,                   # More frequent evaluation
        
        # Logging
        logging_steps=10,
        report_to="wandb",
        
        # Checkpointing
        save_strategy="steps",
        save_steps=50,
        save_total_limit=2,
        
        # Label smoothing for better generalization
        label_smoothing_factor=0.1
    )
    
    # Early stopping with longer patience
    early_stopping = EarlyStoppingCallback(
        early_stopping_patience=3,
        early_stopping_threshold=0.01
    )
    
    # K-fold with stratification
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    texts = balanced_df['Text'].tolist()
    labels = balanced_df['corrected_label'].tolist()
    
    fold_scores = []
    for fold, (train_idx, val_idx) in enumerate(skf.split(texts, labels)):
        print(f"\nTraining fold {fold+1}/5...")
        
        # Prepare datasets with class weights
        train_dataset = tokenize_data(
            [texts[i] for i in train_idx],
            [labels[i] for i in train_idx],
            tokenizer
        )
        val_dataset = tokenize_data(
            [texts[i] for i in val_idx],
            [labels[i] for i in val_idx],
            tokenizer
        )
        
        # Initialize trainer with class weights
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics,
            callbacks=[early_stopping],
            class_weights=class_weights
        )
        
        # Train and evaluate
        trainer.train()
        eval_results = trainer.evaluate()
        fold_scores.append(eval_results)
        
        # Detailed logging
        wandb.log({
            f"fold_{fold+1}/eval_loss": eval_results["eval_loss"],
            f"fold_{fold+1}/accuracy": eval_results["eval_accuracy"],
            f"fold_{fold+1}/precision": eval_results["eval_precision"],
            f"fold_{fold+1}/recall": eval_results["eval_recall"],
            f"fold_{fold+1}/f1": eval_results["eval_f1"],
            f"fold_{fold+1}/confusion_matrix": wandb.plot.confusion_matrix(
                probs=None,
                y_true=labels,
                preds=trainer.predict(val_dataset).predictions.argmax(-1)
            )
        })
    
    # Log final average metrics
    avg_metrics = {
        metric: np.mean([score[metric] for score in fold_scores])
        for metric in fold_scores[0].keys()
    }
    wandb.log({"final_avg_metrics": avg_metrics})
    
    return model, tokenizer

# Initialize and run the sweep with new config
sweep_config = {
    'method': 'bayes',
    'metric': {'name': 'eval_loss', 'goal': 'minimize'},
    'parameters': {
        'learning_rate': {'min': 1e-7, 'max': 1e-6, 'distribution': 'log_uniform'},
        'weight_decay': {'min': 0.7, 'max': 0.9, 'distribution': 'uniform'},
        'dropout': {'values': [0.4, 0.5, 0.6]},
        'warmup_ratio': {'values': [0.2, 0.3, 0.4]},
        'gradient_clip': {'values': [0.2, 0.3, 0.4]}
    }
}

sweep_id = wandb.sweep(sweep_config, project="network-vulnerability-classifier")
wandb.agent(sweep_id, train_with_wandb, count=5)

if __name__ == "__main__":
    print("Starting model retraining process...")
    model, tokenizer = retrain_model()
    validate_model(model, tokenizer) 