import modal
import os
import tempfile
from pathlib import Path

image = (
    modal.Image.from_registry("ubuntu:22.04", add_python="3.11")
    .apt_install([
        "wget", "curl", "gcc", "g++", "libtinfo5", "libz-dev", "libzstd-dev", "zip", "libncurses5-dev", "git", "xz-utils",
        "build-essential", "libxml2-dev", "python3-dev", "python3-pip", "ninja-build", "pkg-config", "lsb-release",
        "software-properties-common", "gnupg"
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
    .pip_install(["numpy", "torch", "torch-geometric", "wllvm"])
    .run_commands([
        "set -x", # Show commands as they execute
        "export MAKEFLAGS=-j8",
        "wget https://github.com/Kitware/CMake/releases/download/v4.0.2/cmake-4.0.2-linux-x86_64.sh",
        "chmod +x cmake-4.0.2-linux-x86_64.sh",
        "mkdir -p /opt/cmake",
        "./cmake-4.0.2-linux-x86_64.sh --skip-license --prefix=/opt/cmake",
        "ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake",
        "cd /root && git clone https://github.com/SVF-tools/SVF.git",
        "cd /root/SVF && export CC=gcc && export CXX=g++ && export LLVM_DIR=/usr/lib/llvm-16 && export PATH=/usr/lib/llvm-16/bin:$PATH && bash ./build.sh"
    ])
    .env({
        "LLVM_DIR": "/usr/lib/llvm-16",
        "CLANG_EXECUTABLE": "/usr/lib/llvm-16/bin/clang",
        "CXX": "/usr/lib/llvm-16/bin/clang++",
        "CC": "/usr/lib/llvm-16/bin/clang",
        "PATH": "/usr/lib/llvm-16/bin:$PATH"
    })
)

app = modal.App("c-code-analyzer")

@app.function(image=image)
def compile_c_code(c_code: str, filename: str = "temp.c") -> str:
    """Compile C code using wllvm and return the path to the compiled file."""
    # Create a temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        # Write the C code to a file
        c_file_path = os.path.join(temp_dir, filename)
        with open(c_file_path, 'w') as f:
            f.write(c_code)
        
        # Compile using wllvm
        output_file = os.path.join(temp_dir, filename.replace('.c', ''))
        os.system(f"wllvm -o {output_file} {c_file_path}")
        
        return output_file

@app.function(image=image)
def extract_bitcode(compiled_file: str) -> str:
    """Extract bitcode from the compiled file."""
    os.system(f"extract-bc {compiled_file}")
    return f"{compiled_file}.bc"

@app.function(image=image)
def run_wpa_analysis(bc_file: str) -> str:
    """Run WPA analysis and generate dot file."""
    dot_file = "svfg_final.dot"
    os.system(f"wpa -ander -svfg -dump-vfg {bc_file}")
    return dot_file

@app.function(image=image)
def predict_vulnerability(dot_file: str) -> dict:
    """Run vulnerability prediction on the dot file."""
    from e2e import predict_vulnerability
    predicted_cwe, confidence = predict_vulnerability(dot_file)
    return {
        "predicted_cwe": predicted_cwe,
        "confidence": float(confidence)
    }

@app.local_entrypoint()
def main(c_code: str):
    """Main entrypoint that runs the entire analysis pipeline."""
    # Step 1: Compile the C code
    compiled_file = compile_c_code.remote(c_code)
    
    # Step 2: Extract bitcode
    bc_file = extract_bitcode.remote(compiled_file)
    
    # Step 3: Run WPA analysis
    dot_file = run_wpa_analysis.remote(bc_file)
    
    # Step 4: Predict vulnerability
    result = predict_vulnerability.remote(dot_file)
    
    print("Analysis Results:")
    print(f"Predicted CWE: {result['predicted_cwe']}")
    print(f"Confidence: {result['confidence']:.2f}")