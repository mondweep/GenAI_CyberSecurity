import boto3

def add_port_8000():
    try:
        ec2 = boto3.client('ec2')
        
        # Using the security group ID from your output
        security_group_id = 'sg-0fcf582179810b5bc'  # voyager-api-sg
        
        # Add inbound rule for port 8000
        response = ec2.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 8000,
                    'ToPort': 8000,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'Allow API access'}]
                }
            ]
        )
        
        print("✅ Successfully added port 8000 to security group")
        return True
        
    except Exception as e:
        print(f"❌ Error updating security group: {str(e)}")
        return False

if __name__ == "__main__":
    add_port_8000() 