from huggingface_hub import upload_file, login
import getpass
import os

def update_model_card():
    try:
        # Get the absolute path to the model card
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        model_card_path = os.path.join(parent_dir, "model_card.md")
        
        # Login to Hugging Face
        print("Please enter your Hugging Face token (input will be hidden):")
        token = getpass.getpass()
        login(token=token)
        
        # Upload the model card
        print(f"Uploading model card from: {model_card_path}")
        upload_file(
            path_or_fileobj=model_card_path,
            path_in_repo="README.md",
            repo_id="thisismon/network-vulnerability-classifier"
        )
        print("Model card uploaded successfully!")
        
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        raise e

if __name__ == "__main__":
    update_model_card() 