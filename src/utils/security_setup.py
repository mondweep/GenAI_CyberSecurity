import boto3
from dotenv import load_dotenv
import os

def setup_security_group():
    try:
        ec2 = boto3.client('ec2')
        
        # Create security group with more specific name
        group_name = 'voyager-api-public-sg'
        
        # Check if security group already exists
        try:
            response = ec2.describe_security_groups(
                GroupNames=[group_name]
            )
            security_group_id = response['SecurityGroups'][0]['GroupId']
            print(f"Security group {group_name} already exists: {security_group_id}")
            
        except ec2.exceptions.ClientError:
            # Create new security group if it doesn't exist
            response = ec2.create_security_group(
                GroupName=group_name,
                Description='Security group for public Voyager API access'
            )
            security_group_id = response['GroupId']
            
            # Configure inbound rules
            ec2.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    # HTTP
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 80,
                        'ToPort': 80,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP access'}]
                    },
                    # HTTPS
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 443,
                        'ToPort': 443,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS access'}]
                    },
                    # Custom API port (if needed)
                    {
                        'IpProtocol': 'tcp',
                        'FromPort': 8000,
                        'ToPort': 8000,
                        'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'API access'}]
                    }
                ]
            )
            
            # Tag the security group
            ec2.create_tags(
                Resources=[security_group_id],
                Tags=[
                    {'Key': 'Name', 'Value': 'voyager-api-public'},
                    {'Key': 'Environment', 'Value': 'production'}
                ]
            )
            
            print(f"Created new security group: {security_group_id}")
        
        return security_group_id
        
    except Exception as e:
        print(f"Error with security group setup: {str(e)}")
        return None

def verify_public_access(security_group_id):
    try:
        ec2 = boto3.client('ec2')
        response = ec2.describe_security_groups(
            GroupIds=[security_group_id]
        )
        
        # Verify required ports are open
        required_ports = [80, 443, 8000]
        permissions = response['SecurityGroups'][0]['IpPermissions']
        
        for port in required_ports:
            port_open = False
            for permission in permissions:
                if (permission.get('FromPort') == port and 
                    permission.get('ToPort') == port and 
                    any(ip_range['CidrIp'] == '0.0.0.0/0' for ip_range in permission.get('IpRanges', []))):
                    port_open = True
                    break
            if not port_open:
                print(f"Warning: Port {port} is not publicly accessible")
                return False
        
        print("All required ports are publicly accessible")
        return True
        
    except Exception as e:
        print(f"Error verifying public access: {str(e)}")
        return False

if __name__ == "__main__":
    load_dotenv()  # Load environment variables
    
    # Setup security group
    security_group_id = setup_security_group()
    
    if security_group_id:
        # Verify public access
        verify_public_access(security_group_id) 