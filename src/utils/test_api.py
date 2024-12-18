import requests
import json

def test_api_endpoint(url):
    try:
        response = requests.get(f"{url}/health")
        assert response.status_code == 200
        print("API is accessible and healthy!")
        return True
    except Exception as e:
        print(f"Error testing API: {str(e)}")
        return False 