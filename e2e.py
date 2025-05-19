import torch
from torch_geometric.data import Data
from extract_nodes import extract_nodes_and_instructions, parse_instruction
from gensim.models import Word2Vec
import numpy as np
import re
from torch.serialization import add_safe_globals
from lsh_graph_classifier import GraphEncoder, LSHGraphClassifier
import os

# Add safe globals for numpy
add_safe_globals(['numpy.core.multiarray.scalar'])

def load_models():
    """Load the trained models and embeddings."""
    # Load saved LSH classifier
    saved_data = torch.load('/root/lsh_classifier.pt', map_location=torch.device('cpu'), weights_only=False)
    
    # Load Word2Vec model
    word2vec_model = Word2Vec.load("/root/embeddings_output/juliet_medium_node_embeddings.model")
    
    # Load TransE embeddings
    transe_data = torch.load('/root/instruction_embeddings.pt', map_location=torch.device('cpu'), weights_only=False)
    transe_embeddings = transe_data['final_embeddings']
    instruction_triplets = transe_data['instruction_triplets']
    
    # Create instruction to embedding mapping
    instruction_to_embedding = {
        str(triplet): embedding 
        for triplet, embedding in zip(instruction_triplets, transe_embeddings)
    }
    
    return saved_data, word2vec_model, instruction_to_embedding

def create_node_embeddings(nodes, word2vec_model, instruction_to_embedding):
    """Create embeddings for each node in the graph."""
    node_embeddings = {}
    
    for node, (node_type, node_id, raw_instruction) in nodes:
        # Get Word2Vec embedding (8-dim)
        try:
            w2v_embedding = word2vec_model.wv[node_type]
        except KeyError:
            w2v_embedding = np.zeros(8)
        
        # Get TransE embedding (32-dim)
        if raw_instruction:
            opcode, return_type, operand_types = parse_instruction(raw_instruction)
            instruction_key = str((opcode, return_type, tuple(operand_types)))
            try:
                transe_embedding = instruction_to_embedding[instruction_key]
            except KeyError:
                transe_embedding = torch.zeros(32)
        else:
            transe_embedding = torch.zeros(32)
        
        # Combine embeddings
        combined_embedding = torch.cat([
            torch.tensor(w2v_embedding, dtype=torch.float),
            transe_embedding
        ])
        
        node_embeddings[node] = combined_embedding
    
    return node_embeddings

def create_graph_data(dot_file, node_embeddings):
    """Create PyTorch Geometric Data object from dot file."""
    # Read dot file
    with open(dot_file, 'r') as f:
        content = f.read()
    
    # Extract nodes and edges
    nodes = extract_nodes_and_instructions(content)
    
    # Create node features tensor
    num_nodes = len(nodes)
    node_features = torch.zeros((num_nodes, 40))
    
    # Create local node mapping
    local_node_to_idx = {node_id: idx for idx, (node_id, _) in enumerate(nodes)}
    
    # Fill node features
    for local_idx, (node_id, _) in enumerate(nodes):
        if node_id in node_embeddings:
            node_features[local_idx] = node_embeddings[node_id]
    
    # Extract edges
    edge_pattern = r'(Node0x[0-9a-fA-F]+)\s*->\s*(Node0x[0-9a-fA-F]+)'
    edges = re.findall(edge_pattern, content)
    edge_list = []
    
    for src, dst in edges:
        if src in local_node_to_idx and dst in local_node_to_idx:
            src_idx = local_node_to_idx[src]
            dst_idx = local_node_to_idx[dst]
            edge_list.append([src_idx, dst_idx])
    
    edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous() if edge_list else torch.zeros((2, 0), dtype=torch.long)
    
    # Create PyG Data object
    data = Data(
        x=node_features,
        edge_index=edge_index,
        num_nodes=num_nodes
    )
    
    return data

def predict_vulnerability(dot_file):
    """Predict vulnerability from dot file."""
    # Load models
    saved_data, word2vec_model, instruction_to_embedding = load_models()
    
    # Create encoder
    encoder = GraphEncoder(
        input_dim=40,
        hidden_dim=512,
        output_dim=256
    )
    encoder.load_state_dict(saved_data['encoder_state_dict'])
    
    # Create LSH classifier
    classifier = LSHGraphClassifier(
        num_hash_functions=150,
        num_bands=30,
        device='cuda' if torch.cuda.is_available() else 'cpu'
    )
    classifier.projection_vectors = saved_data['projection_vectors']
    classifier.hash_tables = saved_data['hash_tables']
    classifier.graph_embeddings = saved_data['graph_embeddings']
    classifier.graph_labels = saved_data['graph_labels']
    
    # Process dot file
    with open(dot_file, 'r') as f:
        content = f.read()
    nodes = extract_nodes_and_instructions(content)
    
    # Create node embeddings
    node_embeddings = create_node_embeddings(nodes, word2vec_model, instruction_to_embedding)
    
    # Create graph data
    graph_data = create_graph_data(dot_file, node_embeddings)
    
    # Make prediction
    predicted_cwe, confidence = classifier.predict(graph_data, encoder)
    
    return predicted_cwe, confidence

if __name__ == "__main__":
    dot_file = "svfg_final.dot"
    predicted_cwe, confidence = predict_vulnerability(dot_file)
    print(f"Predicted CWE: {predicted_cwe}")
    print(f"Confidence: {confidence:.2f}")