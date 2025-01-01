import pandas as pd
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification, TrainingArguments, Trainer
from sklearn.model_selection import train_test_split
import torch
from datasets import Dataset
from sklearn.metrics import (
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score,
    precision_recall_fscore_support
)
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
        
        # Context-aware pattern matching
        security_contexts = {
            'normal': {
                'authentication': [
                    ('login successful', 'valid credentials'),
                    ('session created', 'authenticated user'),
                    ('mfa verified', 'two-factor complete')
                ],
                'data_access': [
                    ('read operation', 'select query', 'standard access'),
                    ('view product', 'browse catalog', 'list items'),
                    ('download file', 'fetch data', 'retrieve record')
                ],
                'user_activity': [
                    ('user session', 'regular activity', 'standard operation'),
                    ('client request', 'customer access', 'normal traffic'),
                    ('scheduled task', 'automated job', 'routine check')
                ]
            },
            'malicious': {
                'injection': [
                    ('sql injection', 'script injection', 'code injection'),
                    ('malicious payload', 'harmful script', 'exploit code'),
                    ('injection attempt', 'injection detected', 'injection pattern')
                ],
                'authentication_abuse': [
                    ('brute force', 'password spray', 'credential stuffing'),
                    ('auth bypass', 'privilege escalation', 'unauthorized elevation'),
                    ('multiple failed', 'repeated failure', 'login abuse')
                ],
                'suspicious_patterns': [
                    ('port scan', 'network probe', 'vulnerability scan'),
                    ('unusual traffic', 'abnormal pattern', 'suspicious activity'),
                    ('data exfiltration', 'unauthorized transfer', 'suspicious download')
                ]
            }
        }
        
        # Score-based classification
        normal_score = 0
        malicious_score = 0
        
        # Context scoring
        for context, patterns in security_contexts['normal'].items():
            for pattern_group in patterns:
                if any(p in text_lower for p in pattern_group):
                    normal_score += 1
                    # Bonus for multiple matches in same context
                    if sum(p in text_lower for p in pattern_group) > 1:
                        normal_score += 0.5
        
        for context, patterns in security_contexts['malicious'].items():
            for pattern_group in patterns:
                if any(p in text_lower for p in pattern_group):
                    malicious_score += 1.5  # Weight malicious patterns more heavily
                    # Bonus for multiple matches in same context
                    if sum(p in text_lower for p in pattern_group) > 1:
                        malicious_score += 1
        
        # Additional context checks
        def check_timing_patterns(text):
            timing_indicators = {
                'malicious': ['rapid', 'repeated', 'multiple', 'consecutive', 'burst'],
                'normal': ['scheduled', 'periodic', 'regular', 'routine']
            }
            return (sum(t in text_lower for t in timing_indicators['malicious']),
                    sum(t in text_lower for t in timing_indicators['normal']))
        
        def check_data_patterns(text):
            data_indicators = {
                'malicious': ['overflow', 'buffer', 'exploit', 'payload', 'bypass'],
                'normal': ['json', 'xml', 'api', 'request', 'query']
            }
            return (sum(d in text_lower for d in data_indicators['malicious']),
                    sum(d in text_lower for d in data_indicators['normal']))
        
        # Add timing and data pattern scores
        mal_timing, norm_timing = check_timing_patterns(text_lower)
        mal_data, norm_data = check_data_patterns(text_lower)
        
        malicious_score += (mal_timing * 0.5 + mal_data * 0.5)
        normal_score += (norm_timing * 0.3 + norm_data * 0.3)
        
        # Final decision with confidence
        confidence = abs(malicious_score - normal_score) / (malicious_score + normal_score + 1e-6)
        
        if malicious_score > normal_score:
            return 1, confidence
        else:
            return 0, confidence
    
    # Relabel based on enhanced criteria
    print("Relabeling data based on improved criteria...")
    df['corrected_label'] = df['Text'].apply(lambda x: determine_label(x)[0])  # Get label, not tuple
    
    # Verify distribution before augmentation
    print("Pre-augmentation distribution:")
    print(df['corrected_label'].value_counts())
    
    # Balance dataset properly
    min_class_size = min(len(df[df['corrected_label'] == 0]), 
                        len(df[df['corrected_label'] == 1]))
    
    normal_samples = df[df['corrected_label'] == 0].sample(n=min_class_size)
    malicious_samples = df[df['corrected_label'] == 1].sample(n=min_class_size)
    
    balanced_df = pd.concat([normal_samples, malicious_samples])
    
    print("Final distribution:")
    print(balanced_df['corrected_label'].value_counts())
    
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
        # Original text
        augmented_texts.append(text)
        augmented_labels.append(label)
        # Add noise to both normal and malicious
        noisy_text = add_noise_to_text(text, noise_level=0.2)
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
    """Retrain model with improved configuration"""
    
    # Initialize tokenizer first
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
    
    # Initialize model with better regularization
    model = AutoModelForSequenceClassification.from_pretrained(
        "bert-base-uncased",
        num_labels=2,
        hidden_dropout_prob=0.4,           # Moderate dropout
        attention_probs_dropout_prob=0.4,  # Moderate attention dropout
        classifier_dropout=0.4             # Moderate classifier dropout
    ).to(device)
    
    # Adjusted training arguments
    training_args = TrainingArguments(
        output_dir="./balanced_model",
        num_train_epochs=2,                # Reduced epochs
        per_device_train_batch_size=32,    # Larger batch size
        per_device_eval_batch_size=32,
        learning_rate=5e-6,                # Even lower learning rate
        weight_decay=0.4,                  # Increased regularization
        warmup_ratio=0.3,                  # More warmup
        max_grad_norm=0.5,                 # Stricter gradient clipping
        evaluation_strategy="steps",
        eval_steps=50,                     # More frequent evaluation
        save_strategy="steps",
        save_steps=50,
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        label_smoothing_factor=0.2         # Add label smoothing
    )
    
    # Adjusted class weights to be less aggressive
    class_weights = torch.tensor([1.0, 2.0]).to(device)  # Adjust based on class distribution
    
    # Add minimum epochs before early stopping
    early_stopping = EarlyStoppingCallback(
        early_stopping_patience=5,         # Increased patience
        early_stopping_threshold=0.001     # Minimum change to qualify as improvement
    )
    
    # Get balanced dataset
    balanced_df = clean_and_balance_dataset()
    
    # Convert to lists for k-fold
    texts = balanced_df['Text'].tolist()
    labels = balanced_df['corrected_label'].tolist()
    
    # Use k-fold with more folds
    kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    fold_scores = []
    for fold, (train_idx, val_idx) in enumerate(kf.split(texts, labels)):
        print(f"\nTraining fold {fold+1}/5...")
        
        # Get fold's train/val data
        fold_train_texts = [texts[i] for i in train_idx]
        fold_train_labels = [labels[i] for i in train_idx]
        fold_val_texts = [texts[i] for i in val_idx]
        fold_val_labels = [labels[i] for i in val_idx]
        
        # Prepare datasets
        train_dataset = tokenize_data(fold_train_texts, fold_train_labels, tokenizer)
        val_dataset = tokenize_data(fold_val_texts, fold_val_labels, tokenizer)
        
        # Initialize trainer with early stopping
        trainer = Trainer(
            model=model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            compute_metrics=compute_metrics,
            callbacks=[
                early_stopping
            ]
        )
        
        # Train and evaluate
        trainer.train()
        eval_results = trainer.evaluate()
        fold_scores.append(eval_results)
        
        print(f"\nFold {fold+1} Results:")
        print(eval_results)
    
    # Comprehensive testing after training
    print("\nComprehensive Model Validation:")
    test_cases = [
        # Normal cases
        ["User viewing product catalog",
         "Standard GET request to homepage",
         "Successfully logged in to dashboard",
         "Regular database query completed",
         "Normal HTTPS traffic on port 443"],
        
        # Malicious cases
        ["SQL injection attempt detected",
         "Multiple failed login attempts from IP",
         "Port scanning activity detected",
         "Unauthorized access to admin panel",
         "Cross-site scripting attempt blocked"],
        
        # Edge cases
        ["Failed login attempt",  # Could be normal or malicious
         "Database query with special characters",
         "Admin panel access granted",
         "Large file download initiated",
         "Multiple requests from same IP"]
    ]
    
    print("\nTesting with diverse cases:")
    model.eval()
    with torch.no_grad():
        for category in test_cases:
            print(f"\nTesting category:")
            for text in category:
                inputs = tokenizer(text, return_tensors="pt", truncation=True)
                inputs = {k: v.to(device) for k, v in inputs.items()}
                outputs = model(**inputs)
                probs = torch.nn.functional.softmax(outputs.logits, dim=1)[0]
                prediction = outputs.logits.argmax(-1).item()
                confidence = probs[prediction].item()
                
                print(f"\nText: {text}")
                print(f"Prediction: {'Normal' if prediction == 0 else 'Malicious'}")
                print(f"Confidence: {confidence:.2%}")
                print(f"Normal prob: {probs[0]:.2%}")
                print(f"Malicious prob: {probs[1]:.2%}")
    
    # Add adversarial validation during testing
    def test_with_adversarial(text, small_perturbations=True):
        """Test model with slight variations of input."""
        base_inputs = tokenizer(text, return_tensors="pt", truncation=True)
        base_inputs = {k: v.to(device) for k, v in base_inputs.items()}
        
        with torch.no_grad():
            base_output = model(**base_inputs)
            base_pred = base_output.logits.argmax(-1).item()
            base_conf = torch.nn.functional.softmax(base_output.logits, dim=1)[0]
            
            if small_perturbations:
                # Test with minor text variations
                variations = [
                    text.lower(),
                    text.upper(),
                    text + ".",
                    text.replace("to", "2"),
                    text.replace("for", "4")
                ]
                
                all_preds = []
                for var in variations:
                    var_inputs = tokenizer(var, return_tensors="pt", truncation=True)
                    var_inputs = {k: v.to(device) for k, v in var_inputs.items()}
                    var_output = model(**var_inputs)
                    all_preds.append(var_output.logits.argmax(-1).item())
                
                # Check prediction stability
                if len(set(all_preds)) > 1:
                    print(f"WARNING: Unstable predictions for '{text}'")
                    print(f"Variations gave different results: {all_preds}")
        
        return base_pred, base_conf
    
    # Add more comprehensive testing
    test_cases.extend([
        # Edge cases
        ["admin login successful but from new IP",
         "multiple requests but within normal range",
         "failed login followed by success"],
        
        # Mixed signals
        ["unauthorized user with valid credentials",
         "high volume traffic from trusted source",
         "unusual pattern from known user"]
    ])
    
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
    """Quick retraining with bias fixes"""
    run = wandb.init(
        project="network-vulnerability-classifier",
        name=f"debiased-train-{time.strftime('%Y%m%d-%H%M%S')}"
    )
    
    # Get balanced dataset
    balanced_df = clean_and_balance_dataset()
    
    # Initialize model with better defaults
    tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
    model = AutoModelForSequenceClassification.from_pretrained(
        "bert-base-uncased",
        num_labels=2,
        hidden_dropout_prob=0.5,
        attention_probs_dropout_prob=0.5,
        problem_type="single_label_classification"
    ).to(device)
    
    # Better training arguments (ALL duplicates removed)
    training_args = TrainingArguments(
        output_dir=f"./balanced_model_debiased_{run.id}",
        num_train_epochs=2,               # Reduced epochs
        per_device_train_batch_size=16, # Smaller batch size
        per_device_eval_batch_size=16,
        gradient_accumulation_steps=4,
        evaluation_strategy="steps",
        eval_steps=25,                    # More frequent evaluation
        logging_steps=10,
        save_strategy="steps",
        save_steps=50,
        save_total_limit=1,
        fp16=torch.cuda.is_available(),
        learning_rate=2e-5,             # Higher learning rate
        weight_decay=0.1,              # Only one weight_decay parameter
        warmup_ratio=0.1,              # Only warmup parameter
        load_best_model_at_end=True,
        metric_for_best_model="eval_f1",
        greater_is_better=True,
        lr_scheduler_type="cosine",      # Added scheduler
        early_stopping_patience=2,        # Stop earlier if no improvement
        early_stopping_threshold=0.01     # Smaller improvement threshold
    )
    
    # Stratified split to maintain class distribution
    train_texts, val_texts, train_labels, val_labels = train_test_split(
        balanced_df['Text'].tolist(),
        balanced_df['corrected_label'].tolist(),
        test_size=0.2,
        stratify=balanced_df['corrected_label'],  # Ensure balanced split
        random_state=42
    )
    
    # Prepare datasets
    train_dataset = tokenize_data(train_texts, train_labels, tokenizer)
    val_dataset = tokenize_data(val_texts, val_labels, tokenizer)
    
    # Initialize trainer with corrected EarlyStoppingCallback
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        compute_metrics=compute_metrics,
        callbacks=[
            EarlyStoppingCallback(
                early_stopping_patience=3,
                early_stopping_threshold=0.01,
            )
        ]
    )
    
    # Train and evaluate
    trainer.train()
    eval_results = trainer.evaluate()
    
    # Log metrics
    wandb.log(eval_results)
    
    return model, tokenizer

def augment_normal_traffic():
    """Generate more realistic normal traffic patterns"""
    templates = {
        'web_access': [
            "User {user_id} accessed {resource} via {protocol} at {timestamp}",
            "Successful {method} request to {endpoint} from {ip_address}",
            "Client {client_id} performed {action} on {resource} using {auth_method}"
        ],
        'database': [
            "Standard {query_type} operation on {table} by {user_role}",
            "Database {action} completed successfully for {user_id}",
            "Routine {operation} on {database} with {permissions}"
        ],
        'authentication': [
            "User {user_id} logged in with {auth_method} from {location}",
            "Successful authentication for {service} using {protocol}",
            "Valid session created for {user_role} with {access_level}"
        ]
    }
    
    variables = {
        'user_id': [f"user_{i}" for i in range(1000, 9999)],
        'resource': ['product_catalog', 'user_profile', 'order_history', 'settings'],
        'protocol': ['HTTPS', 'TLS 1.3', 'SSH', 'SFTP'],
        'method': ['GET', 'POST', 'PUT', 'PATCH'],
        'auth_method': ['2FA', 'SSO', 'password', 'token'],
        'query_type': ['SELECT', 'INSERT', 'UPDATE', 'JOIN'],
        'operation': ['backup', 'index', 'analyze', 'optimize']
    }
    
    return templates, variables

def validate_label(text, label, confidence):
    """Validate labels with additional security rules"""
    
    # High-risk keywords that should always be reviewed
    high_risk = ['admin', 'root', 'password', 'credential', 'token']
    
    # Suspicious combinations
    suspicious_pairs = [
        ('delete', 'database'),
        ('drop', 'table'),
        ('chmod', '777'),
        ('exec', 'shell')
    ]
    
    needs_review = False
    
    # Check for high-risk keywords
    if any(word in text.lower() for word in high_risk):
        needs_review = True
    
    # Check for suspicious combinations
    if any(all(word in text.lower() for word in pair) for pair in suspicious_pairs):
        needs_review = True
    
    # Low confidence predictions need review
    if confidence < 0.6:
        needs_review = True
    
    return needs_review

# Add class weights to focus more on malicious detection
class_weights = torch.tensor([1.0, 2.0]).to(device)  # Weight malicious class more

# Run single training without sweep
if __name__ == "__main__":
    print("Starting retraining...")
    #model, tokenizer = train_with_wandb()
    model, tokenizer = retrain_model()
    validate_model(model, tokenizer) 

def predict_with_threshold(text, confidence_threshold=0.85):
    outputs = model(**inputs)
    probs = torch.nn.functional.softmax(outputs.logits, dim=1)[0]
    prediction = outputs.logits.argmax(-1).item()
    confidence = probs[prediction].item()
    
    if confidence < confidence_threshold:
        return "Uncertain", confidence
    return "Normal" if prediction == 0 else "Malicious", confidence 

def train_with_cv(n_splits=5):
    kf = KFold(n_splits=n_splits, shuffle=True, random_state=42)
    scores = []
    
    for fold, (train_idx, val_idx) in enumerate(kf.split(texts)):
        print(f"Training fold {fold+1}/{n_splits}")
        # Train model on this fold
        fold_scores = train_fold(train_idx, val_idx)
        scores.append(fold_scores)
    
    return np.mean(scores, axis=0) 