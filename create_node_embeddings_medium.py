import os
import re
import torch
import numpy as np
from gensim.models import Word2Vec
from tqdm import tqdm
from extract_nodes import extract_nodes_and_instructions, parse_instruction
from torch_geometric.data import Data, Dataset
import torch_geometric
from collections import defaultdict

class JulietDataset(Dataset):
    def __init__(self, root, dot_files_list, node_embeddings, node_to_idx, transform=None, pre_transform=None):
        self.dot_files = dot_files_list
        self.node_embeddings = node_embeddings
        self.node_to_idx = node_to_idx
        super().__init__(root, transform, pre_transform)

    def len(self):
        return len(self.dot_files)

    def get(self, idx):
        dot_file = self.dot_files[idx]
        
        # Extract metadata from file path
        parts = dot_file.split('/')
        cwe_type = next(p for p in parts if p.startswith('CWE'))
        is_bad = 'bad' in parts
        filename = parts[-1]
        
        with open(dot_file, 'r') as f:
            content = f.read()
        
        # Extract nodes and sort them by ID
        nodes = extract_nodes_and_instructions(content)
        sorted_nodes = sorted(nodes, key=lambda x: x[0])  # Sort by node ID
        
        # Create local node mapping for this graph
        local_node_to_idx = {node_id: idx for idx, (node_id, _) in enumerate(sorted_nodes)}
        num_nodes = len(sorted_nodes)
        
        # Initialize node features tensor
        node_features = torch.zeros((1400, 40))  # Max nodes × embedding size
        
        # Fill node features in order
        for local_idx, (node_id, _) in enumerate(sorted_nodes):
            node_features[local_idx] = self.node_embeddings[node_id]
        
        # Extract and convert edges using local indices
        edge_pattern = r'(Node0x[0-9a-fA-F]+)\s*->\s*(Node0x[0-9a-fA-F]+)'
        edges = re.findall(edge_pattern, content)
        
        edge_list = []
        for src, dst in edges:
            if src in local_node_to_idx and dst in local_node_to_idx:
                src_idx = local_node_to_idx[src]
                dst_idx = local_node_to_idx[dst]
                edge_list.append([src_idx, dst_idx])
        
        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous() if edge_list else torch.zeros((2, 0), dtype=torch.long)
        
        # Create PyG Data object with metadata
        data = Data(
            x=node_features,
            edge_index=edge_index,
            num_nodes=num_nodes,
            cwe_type=cwe_type,
            is_bad=is_bad,
            filename=filename
        )
        
        return data

def create_node_embeddings(dot_files_dir):
    """Create 40-dimensional node embeddings for all nodes in the dataset."""
    print("Loading Word2Vec model...")
    word2vec_model = Word2Vec.load("embeddings_output/juliet_medium_node_embeddings.model")
    
    print("Loading TransE embeddings...")
    # Load with weights_only=True for security
    transe_data = torch.load('instruction_embeddings.pt', weights_only=True)
    transe_embeddings = transe_data['final_embeddings']
    instruction_triplets = transe_data['instruction_triplets']
    
    # Create instruction to embedding mapping
    instruction_to_embedding = {
        str(triplet): embedding 
        for triplet, embedding in zip(instruction_triplets, transe_embeddings)
    }
    
    # Process all dot files
    all_nodes = {}
    node_to_idx = {}
    current_idx = 0
    
    print("Processing dot files...")
    for root, _, files in os.walk(dot_files_dir):
        for file in tqdm(files):
            if file.endswith('.dot'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r') as f:
                        content = f.read()
                    
                    nodes = extract_nodes_and_instructions(content)
                    
                    for node_id, (node_type, _, raw_instruction) in nodes:
                        if node_id not in node_to_idx:
                            node_to_idx[node_id] = current_idx
                            current_idx += 1
                        
                        if node_id not in all_nodes:
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
                            
                            all_nodes[node_id] = combined_embedding
                
                except Exception as e:
                    print(f"Error processing file {file_path}: {str(e)}")
                    continue
    
    return all_nodes, node_to_idx

def main():
    # Directory containing dot files
    dot_files_dir = 'juliet-medium-ivfg'
    
    # Create output directory if it doesn't exist
    os.makedirs('data/juliet', exist_ok=True)
    
    # Get all dot files
    dot_files = []
    for root, _, files in os.walk(dot_files_dir):
        for file in files:
            if file.endswith('.dot'):
                dot_files.append(os.path.join(root, file))
    
    print(f"Found {len(dot_files)} dot files")
    
    # Create node embeddings
    node_embeddings, node_to_idx = create_node_embeddings(dot_files_dir)
    
    # Create PyG dataset
    dataset = JulietDataset(
        root='data/juliet',
        dot_files_list=dot_files,
        node_embeddings=node_embeddings,
        node_to_idx=node_to_idx
    )
    
    print(f"\nDataset created with {len(dataset)} graphs")
    print(f"Node feature dimension: {dataset[0].x.shape}")
    print(f"Sample metadata:")
    print(f"CWE type: {dataset[0].cwe_type}")
    print(f"Is bad: {dataset[0].is_bad}")
    print(f"Filename: {dataset[0].filename}")
    print(f"Number of edges: {dataset[0].edge_index.shape[1]}")
    
    # Save the dataset
    torch.save(dataset, 'juliet_dataset.pt')
    print("\nDataset saved as 'juliet_dataset.pt'")

if __name__ == "__main__":
    main()