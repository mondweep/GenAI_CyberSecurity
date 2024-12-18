import boto3
from botocore.exceptions import ClientError
from botocore.config import Config
import requests
import socket
import paramiko
import os
from dotenv import load_dotenv
import time

def check_port(host, port):
    """Test if a port is open"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def check_and_start_api(instance, key_path):
    """Check API status without SSH"""
    try:
        print("\nChecking API accessibility:")
        print(f"Instance Public IP: {instance.public_ip_address}")
        print(f"Instance Public DNS: {instance.public_dns_name}")
        
        # Test different endpoints
        endpoints = {
            'health': '/health',
            'api root': '/',
            # Add other endpoints you want to test
        }
        
        for name, path in endpoints.items():
            try:
                # Try both IP and DNS
                urls = [
                    f"http://{instance.public_ip_address}:8000{path}",
                    f"http://{instance.public_dns_name}:8000{path}"
                ]
                
                for url in urls:
                    print(f"\nTesting {name} endpoint: {url}")
                    response = requests.get(url, timeout=5)
                    print(f"✅ {name} endpoint responding:")
                    print(f"   Status: {response.status_code}")
                    print(f"   Response: {response.text[:200]}...")  # First 200 chars
                    
            except requests.exceptions.ConnectionError as e:
                print(f"❌ Cannot connect to {url}")
                print(f"   Error: Connection refused - API might not be running")
            except requests.exceptions.Timeout:
                print(f"❌ Timeout connecting to {url}")
            except Exception as e:
                print(f"❌ Error testing {url}: {str(e)}")
        
        # Test port 8000 directly
        if check_port(instance.public_ip_address, 8000):
            print("✅ Port 8000 is open")
        else:
            print("❌ Port 8000 is not open")
        
        return True
        
    except Exception as e:
        print(f"❌ Error in check_and_start_api: {str(e)}")
        return False

def fix_security_group(security_group_id: str) -> bool:
    """Add port 8000 to security group if it's not already open"""
    try:
        ec2 = boto3.client('ec2')
        
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
        print(f"✅ Successfully added port 8000 to security group {security_group_id}")
        return True
        
    except Exception as e:
        if 'InvalidPermission.Duplicate' in str(e):
            print(f"ℹ️ Port 8000 is already configured in security group {security_group_id}")
            return True
        print(f"❌ Error updating security group: {str(e)}")
        return False

def diagnose_instance():
    try:
        # Load environment variables
        load_dotenv()
        key_path = os.getenv('EC2_KEY_PATH')
        if not key_path:
            print("❌ Error: EC2_KEY_PATH not set in .env file")
            return
        
        # Rest of your existing diagnose_instance code...
        config = Config(
            connect_timeout=5,
            read_timeout=5,
            retries={'max_attempts': 2}
        )
        
        ec2 = boto3.resource('ec2', config=config)
        ec2_client = boto3.client('ec2')
        
        instances = ec2.instances.filter(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        
        print("\nDiagnosing EC2 Instance Configuration:")
        print("-" * 80)
        
        found_instances = False
        for instance in instances:
            found_instances = True
            print("\n1. Basic Instance Information:")
            print(f"   Instance ID: {instance.id}")
            print(f"   Instance Type: {instance.instance_type}")
            print(f"   Launch Time: {instance.launch_time}")
            print(f"   Public IP: {instance.public_ip_address}")
            print(f"   Public DNS: {instance.public_dns_name}")
            
            # Check if instance has public IP
            print("\n2. Public IP Configuration:")
            if instance.public_ip_address:
                print(f"   ✅ Public IP is configured: {instance.public_ip_address}")
            else:
                print("   ❌ No public IP assigned")
            
            # Check Security Groups
            print("\n3. Security Group Configuration:")
            needs_security_fix = False
            for sg in instance.security_groups:
                security_group = ec2.SecurityGroup(sg['GroupId'])
                print(f"\n   Security Group: {sg['GroupName']} ({sg['GroupId']})")
                
                # Check inbound rules
                print("   Inbound Rules:")
                for permission in security_group.ip_permissions:
                    from_port = permission.get('FromPort', 'All')
                    to_port = permission.get('ToPort', 'All')
                    ip_protocol = permission.get('IpProtocol', 'All')
                    
                    for ip_range in permission.get('IpRanges', []):
                        print(f"   - Port {from_port}-{to_port} ({ip_protocol}) from {ip_range.get('CidrIp', 'N/A')}")
                
                # Check specifically for port 8000
                port_8000_open = any(
                    permission.get('FromPort', 0) <= 8000 <= permission.get('ToPort', 0)
                    and any(ip_range.get('CidrIp') == '0.0.0.0/0' for ip_range in permission.get('IpRanges', []))
                    for permission in security_group.ip_permissions
                )
                
                if not port_8000_open:
                    print(f"   ❌ Port 8000 is not publicly accessible in {sg['GroupName']}")
                    if sg['GroupName'] == 'voyager-api-sg':  # Only fix the API security group
                        needs_security_fix = True
                        print("   🔧 Attempting to fix security group configuration...")
                        if fix_security_group(sg['GroupId']):
                            print("   ✅ Security group updated successfully")
                        else:
                            print("   ❌ Failed to update security group")
                else:
                    print(f"   ✅ Port 8000 is open in {sg['GroupName']}")
            
            # Check Network ACLs
            print("\n4. Network ACL Configuration:")
            subnet_id = instance.subnet_id
            subnet = ec2.Subnet(subnet_id)
            network_acl_id = ec2_client.describe_network_acls(
                Filters=[{'Name': 'association.subnet-id', 'Values': [subnet_id]}]
            )['NetworkAcls'][0]['NetworkAclId']
            print(f"   Subnet ID: {subnet_id}")
            print(f"   Network ACL ID: {network_acl_id}")
            
            # Test connectivity
            print("\n5. Connectivity Tests:")
            if instance.public_ip_address:
                # Test port 8000
                port_open = check_port(instance.public_ip_address, 8000)
                print(f"   Port 8000 accessibility: {'✅ Open' if port_open else '❌ Closed'}")
                
                # Test API endpoint
                try:
                    health_url = f"http://{instance.public_ip_address}:8000/health"
                    response = requests.get(health_url, timeout=5)
                    print(f"   API health endpoint: ✅ Responding (Status: {response.status_code})")
                except requests.exceptions.RequestException as e:
                    print(f"   API health endpoint: ❌ Not responding ({str(e)})")
            
            # After connectivity tests, add API service check
            print("\n6. API Service Status:")
            if instance.public_ip_address:
                if check_and_start_api(instance, key_path):
                    print("   ✅ API service check completed")
                else:
                    print("   ❌ API service check failed")
            
            print("\n7. Recommendations:")
            if not instance.public_ip_address:
                print("   - Instance needs a public IP address")
            if not port_8000_open:
                print("   - Add inbound rule for port 8000 in security group")
            if instance.public_ip_address and not port_open:
                print("   - Check if API service is running on the instance")
                print("   - Verify API is listening on 0.0.0.0 and not just localhost")

        if not found_instances:
            print("No running EC2 instances found.")

    except ClientError as e:
        print(f"AWS Error: {e}")
    except Exception as e:
        print(f"Error during diagnosis: {str(e)}")

if __name__ == "__main__":
    diagnose_instance()

# Use this after creating your instance with the instance ID returned 