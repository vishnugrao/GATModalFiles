import modal
import os
import tempfile
from pathlib import Path
import shutil
import requests
from pydantic import BaseModel
from typing import Optional, Dict, Any
import base64

# Pydantic models for request/response validation
class CCodeRequest(BaseModel):
    c_code: str

class CompiledBinaryRequest(BaseModel):
    compiled_binary: str  # base64 encoded

class BCContentRequest(BaseModel):
    bc_content: str  # base64 encoded

class DotContentRequest(BaseModel):
    dot_content: str

class VulnerabilityResponse(BaseModel):
    predicted_cwe: str
    confidence: float

# Create the base image with all required dependencies
image = (
    modal.Image.from_registry("ubuntu:22.04", add_python="3.11")
    .apt_install([
        "wget", "curl", "gcc", "g++", "libtinfo5", "libz-dev", "libzstd-dev", "zip", "libncurses5-dev", "git", "xz-utils",
        "build-essential", "libxml2-dev", "python3-dev", "python3-pip", "ninja-build", "pkg-config", "lsb-release",
        "software-properties-common", "gnupg", "libtool"
    ])
    .run_commands([
        "wget https://apt.llvm.org/llvm.sh",
        "chmod +x llvm.sh",
        "./llvm.sh 16",
        "apt-get update"
    ])
    .apt_install([
        "clang-16", "llvm-16", "libclang-16-dev"
    ])
    .pip_install([
        "numpy", "torch", "torch-geometric", "wllvm", "gensim",
        "tqdm", "scikit-learn", "matplotlib", "seaborn", "pydantic"
    ])
    .run_commands([
        "set -x", # Show commands as they execute
        "export MAKEFLAGS=-j8",
        "wget https://github.com/Kitware/CMake/releases/download/v4.0.2/cmake-4.0.2-linux-x86_64.sh",
        "chmod +x cmake-4.0.2-linux-x86_64.sh",
        "mkdir -p /opt/cmake",
        "./cmake-4.0.2-linux-x86_64.sh --skip-license --prefix=/opt/cmake",
        "ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake",
        "cd /root && git clone https://github.com/SVF-tools/SVF.git",
        "cd /root/SVF && export CC=gcc && export CXX=g++ && export LLVM_DIR=/usr/lib/llvm-16 && export PATH=/usr/lib/llvm-16/bin:$PATH && bash ./build.sh",
        "ls -l /root/SVF",
        "cd /root/SVF && bash -c 'source ./setup.sh'"
    ])
    .env({
        "LLVM_DIR": "/usr/lib/llvm-16",
        "CLANG_EXECUTABLE": "/usr/lib/llvm-16/bin/clang",
        "CXX": "/usr/lib/llvm-16/bin/clang++",
        "CC": "/usr/lib/llvm-16/bin/clang",
        "PATH": "/usr/lib/llvm-16/bin:/root/SVF/Release-build/bin:$PATH",
        "LLVM_COMPILER": "clang",
        "SVF_DIR": "/root/SVF"
    })
    .add_local_python_source("e2e")
    .add_local_python_source("extract_nodes")
    .add_local_python_source("lsh_graph_classifier")
    .add_local_file("lsh_classifier.pt", "/root/lsh_classifier.pt")
    .add_local_file("instruction_embeddings.pt", "/root/instruction_embeddings.pt")
    .add_local_dir("embeddings_output", "/root/embeddings_output")
    .add_local_file("SVF/svf/include/Util/TypeUtil.h", "/root/SVF/svf/include/Util/TypeUtil.h")
    .add_local_file("SVF/svf/include/WPA/Embedding.h", "/root/SVF/svf/include/WPA/Embedding.h")
)

app = modal.App("c-code-analyzer")

@app.function(image=image)
@modal.fastapi_endpoint(method="POST")
def compile_c_code(request: CCodeRequest) -> str:
    """Compile C code using wllvm and return the compiled binary."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Write the C code to a temporary file
        c_file_path = os.path.join(temp_dir, "temp.c")
        with open(c_file_path, 'w') as f:
            f.write(request.c_code)
        
        # Print the file contents for debugging
        # print("C code contents:")
        # os.system(f"cat {c_file_path}")
        os.system("echo ")
        
        # Set up wllvm environment
        os.environ["WLLVM_OUTPUT_LEVEL"] = "DEBUG"
        os.environ["WLLVM_BC_NAME"] = "temp.bc"
        os.environ["LLVM_COMPILER"] = "clang"
        os.environ["LLVM_COMPILER_PATH"] = "/usr/lib/llvm-16/bin"
        
        # Set PATH to include LLVM tools
        llvm_paths = [
            "/usr/lib/llvm-16/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin"
        ]
        os.environ["PATH"] = ":".join(llvm_paths + [os.environ.get("PATH", "")])
        
        # Compile using wllvm with bitcode generation
        output_file = os.path.join(temp_dir, "temp")
        compile_cmd = f"wllvm -o {output_file} {c_file_path} -g"
        
        # Execute compilation and check result
        print(f"Running compilation command: {compile_cmd}")
        result = os.system(compile_cmd)
        
        if result != 0:
            raise RuntimeError(f"Compilation failed with exit code {result}")
        
        # Extract bitcode using wllvm
        extract_cmd = f"extract-bc {output_file}"
        print(f"Running extract-bc command: {extract_cmd}")
        result = os.system(extract_cmd)
        
        if result != 0:
            raise RuntimeError(f"Bitcode extraction failed with exit code {result}")
        
        # Read the bitcode file
        bc_file = f"{output_file}.bc"
        if not os.path.exists(bc_file):
            raise FileNotFoundError(f"Bitcode file {bc_file} was not created")
            
        with open(bc_file, 'rb') as f:
            bitcode = f.read()
            
        print("WLLVM DONE")
        return base64.b64encode(bitcode).decode('utf-8')

@app.function(image=image)
@modal.fastapi_endpoint(method="POST")
def extract_bitcode(request: CompiledBinaryRequest) -> str:
    """Extract bitcode from the compiled binary."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Decode and write the compiled binary to a temporary file
        compiled_file = os.path.join(temp_dir, "temp")
        with open(compiled_file, 'wb') as f:
            f.write(base64.b64decode(request.compiled_binary))
            
        # Set up LLVM environment
        llvm_paths = [
            "/usr/lib/llvm-16/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin"
        ]
        os.environ["PATH"] = ":".join(llvm_paths + [os.environ.get("PATH", "")])
        os.environ["LLVM_COMPILER"] = "clang"
        os.environ["LLVM_COMPILER_PATH"] = "/usr/lib/llvm-16/bin"
        
        # Print debug information
        print("Current PATH:", os.environ["PATH"])
        print("Checking LLVM tools:")
        os.system("which llvm-link")
        os.system("which extract-bc")
        os.system("which clang")
        
        # Verify LLVM tools are available
        required_tools = ["llvm-link", "extract-bc", "clang"]
        for tool in required_tools:
            if not shutil.which(tool):
                raise RuntimeError(f"Required tool {tool} not found in PATH")
            
        # Extract bitcode using subprocess to capture output
        import subprocess
        try:
            # First try to extract bitcode directly
            result = subprocess.run(
                ["extract-bc", compiled_file],
                capture_output=True,
                text=True,
                check=True
            )
            print("extract-bc output:", result.stdout)
            if result.stderr:
                print("extract-bc errors:", result.stderr)
                
            # If that fails, try using llvm-link first
            if not os.path.exists(f"{compiled_file}.bc"):
                print("Trying alternative extraction method...")
                result = subprocess.run(
                    ["llvm-link", compiled_file, "-o", f"{compiled_file}.bc"],
                    capture_output=True,
                    text=True,
                    check=True
                )
                print("llvm-link output:", result.stdout)
                if result.stderr:
                    print("llvm-link errors:", result.stderr)
                    
        except subprocess.CalledProcessError as e:
            print("Command failed with output:", e.output)
            print("Command failed with stderr:", e.stderr)
            raise RuntimeError(f"Failed to extract bitcode: {e.stderr}")
        
        # List directory contents
        print("Directory contents after extraction:")
        os.system(f"ls -la {temp_dir}")
        
        # Read the bitcode file
        bc_file = f"{compiled_file}.bc"
        if not os.path.exists(bc_file):
            raise FileNotFoundError(f"Bitcode file {bc_file} was not created")
            
        with open(bc_file, 'rb') as f:
            bitcode = f.read()
            
        return base64.b64encode(bitcode).decode('utf-8')

@app.function(image=image)
@modal.fastapi_endpoint(method="POST")
def run_wpa_analysis(request: BCContentRequest) -> str:
    """Run WPA analysis and generate dot file content."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Decode and write the bitcode to a temporary file
        bc_file = os.path.join(temp_dir, "temp.bc")
        with open(bc_file, 'wb') as f:
            f.write(base64.b64decode(request.bc_content))
            
        # Set up environment variables
        os.environ["SVF_DIR"] = "/root/SVF"
        os.environ["PATH"] = f"/root/SVF/Release-build/bin:{os.environ.get('PATH', '')}"
        
        # Change to temp directory
        original_dir = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Run WPA analysis with correct flags
            wpa_cmd = f"/root/SVF/Release-build/bin/wpa -ander -svfg -dump-vfg temp.bc"
            
            print(f"Running WPA command: {wpa_cmd}")
            print(f"Current directory: {os.getcwd()}")
            result = os.system(wpa_cmd)
            
            if result != 0:
                raise RuntimeError(f"WPA analysis failed with exit code {result}")
                
            # List directory contents for debugging
            print("Directory contents after WPA analysis:")
            os.system("ls -la")
            
            # Check for dot files in current directory
            dot_files = [f for f in os.listdir('.') if f.endswith('.dot')]
            print(f"Found dot files: {dot_files}")
            
            if not dot_files:
                raise FileNotFoundError(f"No dot file found in {temp_dir} after WPA analysis")
                
            # Use the first dot file found
            dot_file = os.path.join(temp_dir, dot_files[0])
            
            # Read the dot file content
            with open(dot_file, 'r') as f:
                dot_content = f.read()
                
            return dot_content
            
        finally:
            # Change back to original directory
            os.chdir(original_dir)

@app.function(image=image)
@modal.fastapi_endpoint(method="POST")
def predict_vulnerability(request: DotContentRequest) -> VulnerabilityResponse:
    """Run vulnerability prediction on the dot file content."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Write the dot content to a temporary file
        dot_file = os.path.join(temp_dir, "svfg_final.dot")
        with open(dot_file, 'w') as f:
            f.write(request.dot_content)
            
        from e2e import predict_vulnerability
        predicted_cwe, confidence = predict_vulnerability(dot_file)
        
        # Ensure proper type conversion
        try:
            predicted_cwe_str = str(predicted_cwe)
            confidence_float = float(confidence)
            
            return VulnerabilityResponse(
                predicted_cwe=predicted_cwe_str,
                confidence=confidence_float
            )
        except (ValueError, TypeError) as e:
            print(f"Error converting prediction results: {str(e)}")
            print(f"Raw prediction_cwe type: {type(predicted_cwe)}")
            print(f"Raw prediction_cwe value: {predicted_cwe}")
            print(f"Raw confidence type: {type(confidence)}")
            print(f"Raw confidence value: {confidence}")
            raise ValueError(f"Failed to convert prediction results to expected types: {str(e)}")

@app.function(image=image)
def test_extract_bc():
    """Test the extract-bc command with a simple C program."""
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a simple C program
        c_code = """
        #include <stdio.h>
        int main() {
            printf("Hello, World!\\n");
            return 0;
        }
        """
        
        # Write the C code to a file
        c_file = os.path.join(temp_dir, "test.c")
        with open(c_file, 'w') as f:
            f.write(c_code)
            
        # Set PATH to include LLVM tools
        llvm_paths = [
            "/usr/lib/llvm-16/bin",
            "/usr/local/bin",
            "/usr/bin",
            "/bin"
        ]
        os.environ["PATH"] = ":".join(llvm_paths + [os.environ.get("PATH", "")])
        
        # Print debug information
        print("Current PATH:", os.environ["PATH"])
        print("Checking LLVM tools:")
        os.system("which llvm-link")
        os.system("which extract-bc")
        
        # Compile the C program
        print("\nCompiling C program:")
        compile_cmd = f"wllvm -o {os.path.join(temp_dir, 'test')} {c_file}"
        os.system(compile_cmd)
        
        # List directory contents after compilation
        print("\nDirectory contents after compilation:")
        os.system(f"ls -la {temp_dir}")
        
        # Try to extract bitcode
        print("\nExtracting bitcode:")
        extract_cmd = f"extract-bc {os.path.join(temp_dir, 'test')}"
        os.system(extract_cmd)
        
        # List directory contents after extraction
        print("\nDirectory contents after extraction:")
        os.system(f"ls -la {temp_dir}")
        
        # Check if the bitcode file exists
        bc_file = os.path.join(temp_dir, "test.bc")
        if os.path.exists(bc_file):
            print(f"\nBitcode file created successfully: {bc_file}")
            return True
        else:
            print(f"\nBitcode file not created: {bc_file}")
            return False

@app.function(image=image)
@modal.fastapi_endpoint(method="POST")
def orchestrator(request: CCodeRequest) -> VulnerabilityResponse:
    """Main orchestrator for LLM calls when the local entry point is not used"""
    try:
        with modal.enable_output():
            # Step 1: Compile the C code
            compile_response = requests.post(
                "https://vishnugrao--c-code-analyzer-compile-c-code.modal.run",
                json={"c_code": request.c_code}
            )
            compile_response.raise_for_status()
            compiled_binary = compile_response.text  # Already base64 encoded
            
            # Step 2: Extract bitcode
            extract_response = requests.post(
                "https://vishnugrao--c-code-analyzer-extract-bitcode.modal.run",
                json={"compiled_binary": compiled_binary}
            )
            extract_response.raise_for_status()
            bc_content = extract_response.text  # Already base64 encoded
            
            # Step 3: Run WPA analysis
            wpa_response = requests.post(
                "https://vishnugrao--c-code-analyzer-run-wpa-analysis.modal.run",
                json={"bc_content": bc_content}
            )
            wpa_response.raise_for_status()
            dot_content = wpa_response.text
            
            # Step 4: Predict vulnerability
            predict_response = requests.post(
                "https://vishnugrao--c-code-analyzer-predict-vulnerability.modal.run",
                json={"dot_content": dot_content}
            )
            predict_response.raise_for_status()
            result = predict_response.json()
            
            print("Analysis Results:")
            print(f"Predicted CWE: {result['predicted_cwe']}")
            print(f"Confidence: {result['confidence']:.2f}")
            
            return VulnerabilityResponse(**result)
            
    except requests.exceptions.RequestException as e:
        print(f"Error during API call: {str(e)}")
        raise
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        raise

@app.local_entrypoint()
def main(c_code: str):
    """Main entrypoint that runs the entire analysis pipeline."""
    try:
        with modal.enable_output():
            # First test the extract-bc command
            # print("Testing extract-bc command...")
            # test_result = test_extract_bc.remote()
            # if not test_result:
            #     raise RuntimeError("extract-bc test failed")
            
            # Step 1: Compile the C code
            compiled_binary = compile_c_code.remote(c_code)
            print(compiled_binary)
            
            # Step 2: Extract bitcode
            bc_content = extract_bitcode.remote(compiled_binary)
            
            # Step 3: Run WPA analysis
            dot_content = run_wpa_analysis.remote(bc_content)
            
            # Step 4: Predict vulnerability
            result = predict_vulnerability.remote(dot_content)
            
            print("Analysis Results:")
            print(f"Predicted CWE: {result['predicted_cwe']}")
            print(f"Confidence: {result['confidence']:.2f}")
            
            return result
    except Exception as e:
        print(f"Error during analysis: {str(e)}")
        raise