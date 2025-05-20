# GATModalFiles

A Modal-based service for analyzing C code vulnerabilities using graph attention networks.
Full paper available at: <https://drive.google.com/file/d/1H62YbgUAaNcJIRYrPVDUZk2B7hpMD0Ov/view>

## Overview

This service provides an end-to-end pipeline for analyzing C code vulnerabilities:
1. Compiles C code to LLVM bitcode
2. Extracts program analysis graphs
3. Uses graph attention networks to predict potential vulnerabilities

## Setup

The service is deployed on Modal and requires the following dependencies:
- Python 3.11
- LLVM 16
- PyTorch
- PyTorch Geometric
- SVF (Static Value-Flow Analysis)

## Usage

### Local Development

```python
from example import main

# Analyze C code
result = main(c_code="your_c_code_here")
print(f"Predicted CWE: {result['predicted_cwe']}")
print(f"Confidence: {result['confidence']:.2f}")
```

### API Endpoints

The service exposes the following Modal endpoints:

1. `compile_c_code`: Compiles C code to LLVM bitcode
2. `extract_bitcode`: Extracts bitcode from compiled binary
3. `run_wpa_analysis`: Runs WPA analysis and generates dot file
4. `predict_vulnerability`: Predicts vulnerabilities from dot file
5. `orchestrator`: Main endpoint that runs the entire pipeline

## Dependencies

- modal
- torch
- torch-geometric
- gensim
- numpy
- pydantic
- requests

## Models

The service uses pre-trained models:
- LSH Graph Classifier (`lsh_classifier.pt`)
- Word2Vec embeddings (`juliet_medium_node_embeddings.model`)
- TransE embeddings (`instruction_embeddings.pt`)
