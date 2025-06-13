import hashlib
import requests
import json
import time
import os

# Calculate SHA-256 hash of the file
def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Set up the test environment
def setup_environment():
    # Set USE_LLM_ORCHESTRATOR to true for testing
    os.environ['USE_LLM_ORCHESTRATOR'] = 'true'
    print("Set USE_LLM_ORCHESTRATOR to true for testing")

# Reset the environment
def reset_environment():
    # Reset USE_LLM_ORCHESTRATOR to false
    os.environ['USE_LLM_ORCHESTRATOR'] = 'false'
    print("Reset USE_LLM_ORCHESTRATOR to false")

# Main function
def main():
    try:
        # Setup the environment
        setup_environment()

        # File to test
        file_path = 'uploads/image.png'

        # Calculate SHA-256 hash
        file_sha = calculate_sha256(file_path)
        print(f"File SHA-256: {file_sha}")

        # API endpoint
        api_url = 'http://localhost:8000/api/extract'

        # Request data
        data = {
            'file_sha': file_sha,
            'extraction_method': 'zsteg',
            'parameters': {}
        }

        # Make API call
        print(f"Making API call to {api_url} with data: {json.dumps(data, indent=2)}")
        response = requests.post(api_url, json=data)

        # Print response
        print(f"Response status code: {response.status_code}")
        print(f"Response body: {json.dumps(response.json(), indent=2)}")

        # If the extraction is asynchronous, wait for it to complete
        if response.status_code == 200 and response.json().get('is_async'):
            task_id = response.json().get('task_id')
            print(f"Extraction is asynchronous. Task ID: {task_id}")

            # Wait for the task to complete
            max_wait = 120  # seconds
            start_time = time.time()

            while time.time() - start_time < max_wait:
                # Check task status
                status_url = f'http://localhost:8000/api/tasks/{task_id}'
                status_response = requests.get(status_url)

                if status_response.status_code == 200:
                    status_data = status_response.json()
                    print(f"Task status: {status_data.get('state')}")

                    if status_data.get('state') in ['SUCCESS', 'FAILURE']:
                        print(f"Task completed with result: {json.dumps(status_data.get('result'), indent=2)}")
                        break

                # Wait a bit before checking again
                time.sleep(5)

            if time.time() - start_time >= max_wait:
                print(f"Task did not complete in {max_wait} seconds")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Reset the environment
        reset_environment()

if __name__ == "__main__":
    main()
