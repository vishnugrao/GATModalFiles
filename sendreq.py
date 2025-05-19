import requests
import json
import os
import base64

def read_c_code(file_path):
    with open(file_path, 'r') as f:
        return f.read()

def main():
    # Read the C code from the file
    c_code = read_c_code('./trial.c')
    
    # Prepare the request data
    data = {
        "c_code": c_code
    }
    
    # Send the request
    try:
        response = requests.post(
            "https://vishnugrao--c-code-analyzer-orchestrator-dev.modal.run",
            json=data,
            headers={"Content-Type": "application/json"}
        )
        
        # Check if the request was successful
        response.raise_for_status()
        
        # Print the results
        result = response.json()
        print("\nAnalysis Results:")
        print(f"Predicted CWE: {result['predicted_cwe']}")
        print(f"Confidence: {result['confidence']:.2f}")
        
    except requests.exceptions.RequestException as e:
        print(f"Error making request: {str(e)}")
        if hasattr(e.response, 'text'):
            print(f"Response text: {e.response.text}")
    except json.JSONDecodeError as e:
        print(f"Error parsing response: {str(e)}")
    except Exception as e:
        print(f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    main()