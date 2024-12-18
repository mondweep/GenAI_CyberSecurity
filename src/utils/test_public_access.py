import requests
import json
import time
from typing import Dict, Any
import os
from dotenv import load_dotenv

class APITester:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip('/')
        self.test_results: Dict[str, Any] = {}

    def test_endpoint(self, endpoint: str, method: str = 'GET', data: dict = None) -> bool:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            if method.upper() == 'GET':
                response = requests.get(url, timeout=10)
            else:
                response = requests.post(url, json=data, timeout=10)
            
            self.test_results[endpoint] = {
                'status_code': response.status_code,
                'response': response.json() if response.status_code == 200 else None,
                'success': response.status_code == 200
            }
            return response.status_code == 200
        except Exception as e:
            self.test_results[endpoint] = {
                'error': str(e),
                'success': False
            }
            return False

    def run_all_tests(self) -> bool:
        """Run all API tests and return overall success status"""
        endpoints = [
            {'path': 'health', 'method': 'GET'},
            {'path': 'predict', 'method': 'POST', 'data': {'input': 'test message'}}
        ]

        all_successful = True
        for endpoint in endpoints:
            print(f"\nTesting endpoint: {endpoint['path']}")
            success = self.test_endpoint(
                endpoint['path'],
                endpoint.get('method', 'GET'),
                endpoint.get('data')
            )
            if success:
                print(f"✅ {endpoint['path']} test passed")
            else:
                print(f"❌ {endpoint['path']} test failed")
            all_successful = all_successful and success

        return all_successful

    def generate_kaggle_notebook(self) -> str:
        """Generate Kaggle-compatible test code"""
        notebook_code = """
import requests
import json

def test_api_endpoint():
    BASE_URL = "{}"
    
    # Test health endpoint
    health_response = requests.get(f"{BASE_URL}/health")
    print(f"Health check status: {health_response.status_code}")
    
    # Test prediction endpoint
    test_data = {{"input": "test message"}}
    predict_response = requests.post(f"{BASE_URL}/predict", json=test_data)
    print(f"Prediction status: {predict_response.status_code}")
    
    if predict_response.status_code == 200:
        print(f"Prediction response: {predict_response.json()}")
        
test_api_endpoint()
""".format(self.base_url)
        
        # Save notebook code to file
        with open('kaggle_test_notebook.py', 'w') as f:
            f.write(notebook_code)
        
        return notebook_code

def main():
    # Load environment variables from .env file
    load_dotenv()
    
    # Get API endpoint from environment variables
    API_ENDPOINT = os.getenv('API_ENDPOINT')
    
    if not API_ENDPOINT:
        print("❌ Error: API_ENDPOINT not found in .env file")
        print("Please add API_ENDPOINT=http://your-api-url:port to your .env file")
        return
    
    print(f"Using API endpoint: {API_ENDPOINT}")
    tester = APITester(API_ENDPOINT)
    
    print("\nTesting API public access...")
    success = tester.run_all_tests()
    
    if success:
        print("\n✅ All tests passed! API is publicly accessible")
        print("\nGenerating Kaggle test notebook...")
        tester.generate_kaggle_notebook()
        print("Kaggle test notebook generated: kaggle_test_notebook.py")
    else:
        print("\n❌ Some tests failed. Please check the results:")
        print(json.dumps(tester.test_results, indent=2))

if __name__ == "__main__":
    main() 