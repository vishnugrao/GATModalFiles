import torch
from e2e import predict_vulnerability

def main():
    # Path to the dot file
    dot_file = "svfg_final.dot"
    
    # Make prediction
    predicted_cwe, confidence = predict_vulnerability(dot_file)
    
    print(f"Predicted CWE: {predicted_cwe}")
    print(f"Confidence: {confidence:.2f}")

if __name__ == "__main__":
    main() 