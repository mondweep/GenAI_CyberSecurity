# Import necessary libraries
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
from datetime import datetime
from io import StringIO
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import argparse
import json
import sys

# Get the script directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Get the project root (two levels up from script directory)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Update paths for results directories
results_dir = os.path.join(SCRIPT_DIR, 'results')
if not os.path.exists(results_dir):
    os.makedirs(results_dir)

# Update the CSV reading line to use project root
csv_path = os.path.join(PROJECT_ROOT, 'input', 'cyber-security-incidents', 'incidents.csv')
print(f"Attempting to read CSV from: {csv_path}")  # Debug print
df = pd.read_csv(csv_path)

# Download all required NLTK data
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('punkt_tab')
nltk.download('averaged_perceptron_tagger')
nltk.download('wordnet')

# Define preprocessing function
def preprocess_text(text):
    # Convert to lowercase
    text = str(text).lower()
    # Remove special characters and digits
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    # Simple word splitting
    tokens = text.split()
    # Remove stopwords
    stop_words = set(stopwords.words('english'))
    tokens = [t for t in tokens if t not in stop_words]
    return ' '.join(tokens)

# Create a text file for logging results
log_file = os.path.join(results_dir, 'analysis_results.txt')

# Function to log text output
def log_result(text, file=log_file):
    with open(file, 'a') as f:
        f.write(text + '\n')

# Clear previous results
with open(log_file, 'w') as f:
    f.write(f"Analysis Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    f.write("="*50 + "\n\n")

# 1. Data Preprocessing
missing_values = df.isnull().sum()
log_result("Missing values:\n" + missing_values.to_string())

# Basic information about the dataset - Fixed version
buffer = StringIO()
df.info(buf=buffer)
log_result("\nDataset Info:\n" + "".join(buffer.getvalue().splitlines()))

# 2. Calculate average vulnerability type distribution
vuln_dist = df['Vulnerability Type'].value_counts()
log_result("\nVulnerability Type Distribution:\n" + vuln_dist.to_string())

# 3. Create visualization for vulnerability types
plt.figure(figsize=(12, 6))
sns.barplot(x=vuln_dist.index, y=vuln_dist.values)
plt.xticks(rotation=45)
plt.title('Distribution of Vulnerability Types')
plt.xlabel('Vulnerability Type')
plt.ylabel('Count')
plt.tight_layout()
plt.savefig(os.path.join(results_dir, 'vulnerability_distribution.png'))
plt.close()

# 4. Time-based analysis
df['Timestamp'] = pd.to_datetime(df['Timestamp'])
df['month'] = df['Timestamp'].dt.month
df['year'] = df['Timestamp'].dt.year

monthly_incidents = df.groupby('month')['ID'].count()
plt.figure(figsize=(10, 5))
sns.lineplot(x=monthly_incidents.index, y=monthly_incidents.values)
plt.title('Number of Incidents by Month')
plt.xlabel('Month')
plt.ylabel('Number of Incidents')
plt.savefig(os.path.join(results_dir, 'monthly_incidents.png'))
plt.close()

# 5. Label distribution analysis
label_dist = df['Label'].value_counts()
log_result("\nLabel Distribution:\n" + label_dist.to_string())

# 6. Correlation analysis
correlation_matrix = df.select_dtypes(include=[np.number]).corr()
plt.figure(figsize=(10, 8))
sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm')
plt.title('Correlation Matrix')
plt.tight_layout()
plt.savefig(os.path.join(results_dir, 'correlation_matrix.png'))
plt.close()

# 7. Text length analysis
df['text_length'] = df['Text'].str.len()
plt.figure(figsize=(10, 6))
sns.histplot(data=df, x='text_length', bins=50)
plt.title('Distribution of Text Length')
plt.xlabel('Text Length')
plt.ylabel('Count')
plt.savefig(os.path.join(results_dir, 'text_length_distribution.png'))
plt.close()

# 8. Vulnerability Type vs Label
plt.figure(figsize=(12, 6))
sns.boxplot(data=df, x='Vulnerability Type', y='Label')
plt.xticks(rotation=45)
plt.title('Label Distribution by Vulnerability Type')
plt.tight_layout()
plt.savefig(os.path.join(results_dir, 'vulnerability_vs_label.png'))
plt.close()

# Save summary statistics
summary_stats = df.describe()
log_result("\nSummary Statistics:\n" + summary_stats.to_string())

# Text preprocessing
log_result("\nPerforming text preprocessing...")
df['processed_text'] = df['Text'].apply(preprocess_text)

# TF-IDF Vectorization
vectorizer = TfidfVectorizer(max_features=1000)
X = vectorizer.fit_transform(df['processed_text'])
y = df['Label']

# Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
log_result("\nTraining Logistic Regression model...")
model = LogisticRegression(max_iter=1000)
model.fit(X_train, y_train)

# Make predictions directly on X_test (it's already transformed)
y_pred = model.predict(X_test)

# Model evaluation
log_result("\nClassification Report:")
log_result(classification_report(y_test, y_pred))

# Confusion Matrix visualization
plt.figure(figsize=(8, 6))
sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt='d', cmap='Blues')
plt.title('Confusion Matrix')
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.savefig(os.path.join(results_dir, 'confusion_matrix.png'))
plt.close()

# Feature importance analysis
feature_importance = pd.DataFrame({
    'feature': vectorizer.get_feature_names_out(),
    'importance': abs(model.coef_[0])
})
feature_importance = feature_importance.sort_values('importance', ascending=False)
log_result("\nTop 10 Most Important Features:")
log_result(feature_importance.head(10).to_string())

# Vulnerability type analysis with labels
vuln_label_dist = pd.crosstab(df['Vulnerability Type'], df['Label'])
log_result("\nVulnerability Type vs Label Distribution:")
log_result(vuln_label_dist.to_string())

# Save model and vectorizer
import joblib
joblib.dump(model, os.path.join(results_dir, 'model.pkl'))
joblib.dump(vectorizer, os.path.join(results_dir, 'vectorizer.pkl'))

print(f"Analysis complete. Results saved in {results_dir}/")

# Add this class after the existing imports
class SecurityAnalysis:
    def __init__(self):
        self.results_dir = os.path.join(SCRIPT_DIR, 'security_results')
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
    
    def generate_key(self, password: str, salt: bytes = None) -> tuple:
        """Generate a key using password and salt"""
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return key, salt

    def encrypt_message(self, message: str, key: bytes) -> tuple:
        """Encrypt a message using AES-CBC"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Ensure proper padding and encoding
        padded_message = self._pad_message(message.encode('utf-8'))
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        
        return base64.b64encode(ciphertext), iv

    def decrypt_message(self, encrypted_message: bytes, key: bytes, iv: bytes) -> str:
        """Decrypt a message using AES-CBC"""
        try:
            # Decode base64 first
            encrypted_bytes = base64.b64decode(encrypted_message)
            
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Decrypt and unpad
            padded_plaintext = decryptor.update(encrypted_bytes) + decryptor.finalize()
            unpadded_plaintext = self._unpad_message(padded_plaintext)
            
            return unpadded_plaintext.decode('utf-8')
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None

    def _pad_message(self, message: bytes) -> bytes:
        """Add PKCS7 padding"""
        block_size = 16
        padding_length = block_size - (len(message) % block_size)
        padding = bytes([padding_length] * padding_length)
        return message + padding

    def _unpad_message(self, padded_message: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = padded_message[-1]
        if padding_length > 16:
            raise ValueError("Invalid padding")
        return padded_message[:-padding_length]

    def test_encryption_workflow(self, message: str, password: str):
        """Test the complete encryption/decryption workflow"""
        results = []
        
        # Generate key
        key, salt = self.generate_key(password)
        results.append(f"Generated key from password with salt: {base64.b64encode(salt).decode()}")
        
        # Encrypt message
        encrypted, iv = self.encrypt_message(message, key)
        results.append(f"Encrypted message: {encrypted.decode()}")
        
        # Decrypt message
        decrypted = self.decrypt_message(encrypted, key, iv)
        results.append(f"Decrypted message: {decrypted}")
        
        # Save results
        with open(os.path.join(self.results_dir, 'security_test_results.txt'), 'w') as f:
            f.write('\n'.join(results))
        
        return results

# Add this to the main analysis script
def run_security_analysis():
    security = SecurityAnalysis()
    
    # Test the encryption workflow
    test_message = "This is a test message for encryption"
    test_password = "secure_password123"
    
    results = security.test_encryption_workflow(test_message, test_password)
    
    # Log security analysis results
    log_result("\nSecurity Analysis Results:")
    for result in results:
        log_result(result)

# Add this after the SecurityAnalysis class definition

def test_encryption_workflow():
    """Test the complete encryption/decryption workflow with multiple messages"""
    security = SecurityAnalysis()
    
    # Test cases
    test_cases = [
        ("This is a secret message", "password123"),
        ("Another confidential text", "strongpass456"),
        ("Sensitive data here", "secure789")
    ]
    
    results = []
    for message, password in test_cases:
        # Generate key
        key, salt = security.generate_key(password)
        results.append(f"\nTest with message: '{message}' and password: '{password}'")
        results.append(f"Generated salt: {base64.b64encode(salt).decode()}")
        
        # First encryption
        encrypted1, iv1 = security.encrypt_message(message, key)
        results.append(f"First encryption: {encrypted1.decode()}")
        
        # Second encryption (should be different due to different IV)
        encrypted2, iv2 = security.encrypt_message(message, key)
        results.append(f"Second encryption: {encrypted2.decode()}")
        
        # Verify different IVs produce different results
        results.append(f"Encryptions are different: {encrypted1 != encrypted2}")
        
        # Decrypt and verify
        decrypted = security.decrypt_message(encrypted1, key, iv1)
        results.append(f"Decrypted message matches: {decrypted == message}")
    
    # Save results
    with open(os.path.join(security.results_dir, 'encryption_test_results.txt'), 'w') as f:
        f.write('\n'.join(results))
    
    return results

# Integration with Voyager project
class VoyagerIntegration:
    def __init__(self):
        self.security = SecurityAnalysis()
    
    def encrypt_voyager_data(self, data: dict, password: str) -> dict:
        """Encrypt data for Voyager storage"""
        key, salt = self.security.generate_key(password)
        encrypted_data = {}
        
        for field, value in data.items():
            if isinstance(value, str):
                encrypted_value, iv = self.security.encrypt_message(value, key)
                encrypted_data[field] = {
                    'encrypted': encrypted_value.decode(),  # Already base64 encoded
                    'iv': base64.b64encode(iv).decode(),
                    'salt': base64.b64encode(salt).decode()
                }
            else:
                encrypted_data[field] = value
        
        return encrypted_data
    
    def decrypt_voyager_data(self, encrypted_data: dict, password: str) -> dict:
        """Decrypt data from Voyager storage"""
        decrypted_data = {}
        
        for field, value in encrypted_data.items():
            if isinstance(value, dict) and 'encrypted' in value:
                key, _ = self.security.generate_key(
                    password, 
                    base64.b64decode(value['salt'])
                )
                decrypted_value = self.security.decrypt_message(
                    base64.b64decode(value['encrypted']),
                    key,
                    base64.b64decode(value['iv'])
                )
                decrypted_data[field] = decrypted_value
            else:
                decrypted_data[field] = value
        
        return decrypted_data

# Add this after the model prediction section
def save_model_metrics(y_test, y_pred, results_dir):
    """Save model performance metrics"""
    # Generate classification report
    class_report = classification_report(y_test, y_pred)
    
    # Save classification report
    with open(os.path.join(results_dir, 'model_performance.txt'), 'w') as f:
        f.write("Classification Report:\n")
        f.write("====================\n")
        f.write(class_report)
        
        # Add additional metrics if needed
        f.write("\nConfusion Matrix:\n")
        f.write("================\n")
        f.write(str(confusion_matrix(y_test, y_pred)))

# Update the model training section
# ... existing code ...
y_pred = model.predict(X_test)

# Save model metrics
save_model_metrics(y_test, y_pred, results_dir)

# Continue with existing confusion matrix visualization
plt.figure(figsize=(8, 6))
sns.heatmap(confusion_matrix(y_test, y_pred), annot=True, fmt='d')
plt.title('Confusion Matrix')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.savefig(os.path.join(results_dir, 'confusion_matrix.png'))
plt.close()

def handle_chat_encryption(messages, password):
    security = SecurityAnalysis()
    key, salt = security.generate_key(password)
    
    encrypted_messages = []
    for message in messages:
        if message.get('sensitive', False):
            encrypted, iv = security.encrypt_message(message['content'], key)
            encrypted_messages.append({
                **message,
                'content': encrypted.decode(),
                'iv': base64.b64encode(iv).decode(),
                'encrypted': True
            })
        else:
            encrypted_messages.append(message)
    
    return {
        'messages': encrypted_messages,
        'salt': base64.b64encode(salt).decode()
    }

def handle_cli():
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['encrypt', 'decrypt'])
    parser.add_argument('--data', type=str)
    parser.add_argument('--password', type=str)
    
    args = parser.parse_args()
    security = SecurityAnalysis()
    
    if args.mode == 'encrypt':
        data = json.loads(args.data)
        if 'messages' in data:
            # Handle chat messages
            result = handle_chat_encryption(data['messages'], args.password)
        else:
            # Handle regular encryption
            key, salt = security.generate_key(args.password)
            encrypted, iv = security.encrypt_message(json.dumps(data), key)
            result = {
                'encrypted': encrypted.decode(),
                'salt': base64.b64encode(salt).decode(),
                'iv': base64.b64encode(iv).decode()
            }
        print(json.dumps(result))

# Modify your existing main block to look like this:
if __name__ == '__main__':
    # Check if command line arguments are provided
    if len(sys.argv) > 1:
        handle_cli()
    else:
        # Your existing main code
        print(f"Analysis complete. Results saved in {results_dir}/") 