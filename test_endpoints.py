import modal
from example import app

# Test C code with a potential buffer overflow vulnerability
TEST_CODE = """
#include <stdio.h>
#include <string.h>

void vulnerable_function(char* input) {
    char buffer[10];
    strcpy(buffer, input);  // Potential buffer overflow
}

int main() {
    char* long_string = "This is a very long string that will cause a buffer overflow";
    vulnerable_function(long_string);
    return 0;
}
"""

def test_pipeline():
    """Test the entire vulnerability analysis pipeline."""
    # Step 1: Compile the C code
    print("Step 1: Compiling C code...")
    compiled_file = app.compile_c_code.remote(TEST_CODE)
    print(f"Compiled file: {compiled_file}")
    
    # Step 2: Extract bitcode
    print("\nStep 2: Extracting bitcode...")
    bc_file = app.extract_bitcode.remote(compiled_file)
    print(f"Bitcode file: {bc_file}")
    
    # Step 3: Run WPA analysis
    print("\nStep 3: Running WPA analysis...")
    dot_file = app.run_wpa_analysis.remote(bc_file)
    print(f"Generated dot file: {dot_file}")
    
    # Step 4: Predict vulnerability
    print("\nStep 4: Predicting vulnerability...")
    result = app.predict_vulnerability.remote(dot_file)
    print("\nAnalysis Results:")
    print(f"Predicted CWE: {result['predicted_cwe']}")
    print(f"Confidence: {result['confidence']:.2f}")

if __name__ == "__main__":
    test_pipeline() 