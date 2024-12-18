import boto3
import os
from dotenv import load_dotenv

def create_ec2_instance():
    try:
        load_dotenv()
        ec2 = boto3.resource('ec2')
        
        # Create EC2 instance
        instance = ec2.create_instances(
            ImageId='ami-0c7217cdde317cfec',  # Amazon Linux 2023 AMI
            InstanceType='t2.micro',
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'Name',
                            'Value': 'voyager-api'
                        },
                    ]
                },
            ]
        )[0]
        
        print(f"Created EC2 instance: {instance.id}")
        return instance.id
        
    except Exception as e:
        print(f"Error creating EC2 instance: {str(e)}")
        return None

if __name__ == "__main__":
    create_ec2_instance() 