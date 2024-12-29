import os
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from huggingface_hub import login
import getpass

def upload_model():
    try:
        # Prompt for Hugging Face token securely
        print("Please enter your Hugging Face token (input will be hidden):")
        token = getpass.getpass()
        
        # Login to Hugging Face using Method 3
        login(token=token)
        
        # Load your trained model from the results directory
        results_dir = "./results"
        # Find the best checkpoint
        checkpoints = [d for d in os.listdir(results_dir) if d.startswith('checkpoint')]
        best_checkpoint = sorted(checkpoints)[-1]  # Get the latest checkpoint
        model_path = os.path.join(results_dir, best_checkpoint)
        
        print(f"Loading model from: {model_path}")
        
        # Load model and tokenizer
        model = AutoModelForSequenceClassification.from_pretrained(model_path)
        tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
        
        # Push to Hugging Face Hub
        print("Uploading to Hugging Face Hub...")
        model.push_to_hub("thisismon/network-vulnerability-classifier")
        tokenizer.push_to_hub("thisismon/network-vulnerability-classifier")
        
        print("Upload completed successfully!")
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        raise e

if __name__ == "__main__":
    upload_model() 