import boto3
import os
from dotenv import load_dotenv

def verify_aws_connection():
    try:
        # Create an AWS session
        session = boto3.Session()
        
        # Get the caller identity to verify credentials
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        
        print("Successfully connected to AWS!")
        print(f"Account ID: {identity['Account']}")
        print(f"User ARN: {identity['Arn']}")
        return True
        
    except Exception as e:
        print(f"Error connecting to AWS: {str(e)}")
        return False

if __name__ == "__main__":
    load_dotenv()
    verify_aws_connection() 