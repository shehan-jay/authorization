import requests

def call_public_endpoint():
    try:
        response = requests.get('http://localhost:5000/api/public')
        print(f'Status Code: {response.status_code}')
        print(f'Response: {response.json()}')
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == '__main__':
    print("Testing public endpoint...")
    call_public_endpoint() 