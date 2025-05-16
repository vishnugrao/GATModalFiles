import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data, Dataset, DataLoader
from torch_geometric.nn import global_mean_pool, GCNConv, global_max_pool
import numpy as np
from collections import defaultdict
from tqdm import tqdm
from sklearn.metrics import classification_report
import random
from typing import List, Dict, Set, Tuple
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import re
from extract_nodes import extract_nodes_and_instructions
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA
from torch.optim.lr_scheduler import ReduceLROnPlateau

class JulietDataset(Dataset):
    def __init__(self, root, dot_files=None, node_embeddings=None, node_to_idx=None, transform=None, pre_transform=None):
        self.dot_files = dot_files
        self.node_embeddings = node_embeddings
        self.node_to_idx = node_to_idx
        self._data_list = []
        super().__init__(root, transform, pre_transform)
        
        if dot_files is not None:
            print("Processing dot files...")
            self._process_dot_files()

    def _process_dot_files(self):
        for dot_file in tqdm(self.dot_files, desc="Loading graphs"):
            try:
                with open(dot_file, 'r') as f:
                    content = f.read()
                
                # Extract metadata
                parts = str(dot_file).split('/')
                cwe_match = re.search(r'CWE(\d+)', str(dot_file))
                cwe_number = int(cwe_match.group(1)) if cwe_match else -1
                is_bad = 'bad' in parts
                filename = parts[-1]
                
                # Only process bad samples
                if not is_bad:
                    continue
                
                # Extract and sort nodes
                nodes = extract_nodes_and_instructions(content)
                sorted_nodes = sorted(nodes, key=lambda x: x[0])
                
                # Create local node mapping
                local_node_to_idx = {node_id: idx for idx, (node_id, _) in enumerate(sorted_nodes)}
                num_nodes = len(sorted_nodes)
                
                # Create node features
                node_features = torch.zeros((num_nodes, 40))  # Using embedding dimension from node_embeddings
                for local_idx, (node_id, _) in enumerate(sorted_nodes):
                    if node_id in self.node_embeddings:
                        node_features[local_idx] = self.node_embeddings[node_id]
                
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
                
                # Create Data object
                data = Data(
                    x=node_features,
                    edge_index=edge_index,
                    y=torch.tensor([cwe_number]),
                    num_nodes=num_nodes,
                    filename=filename
                )
                
                self._data_list.append(data)
                
            except Exception as e:
                print(f"Error processing file {dot_file}: {str(e)}")
                continue

    def len(self):
        return len(self._data_list)

    def get(self, idx):
        return self._data_list[idx]

    @property
    def raw_file_names(self):
        return []

    @property
    def processed_file_names(self):
        return []

    def process(self):
        pass

class LSHGraphClassifier:
    def __init__(self, num_hash_functions: int = 200, num_bands: int = 25, device='cpu'):
        """Initialize LSH-based graph classifier"""
        self.num_hash_functions = num_hash_functions
        self.num_bands = num_bands
        self.rows_per_band = num_hash_functions // num_bands
        self.hash_tables: List[Dict[str, Set[int]]] = [defaultdict(set) for _ in range(num_bands)]
        self.graph_embeddings = {}
        self.graph_labels = {}
        self.projection_vectors = None
        self.device = device
        
    def _generate_projection_vectors(self, embedding_dim: int):
        """Generate random projection vectors for LSH"""
        self.projection_vectors = torch.randn(self.num_hash_functions, embedding_dim).to(self.device)
        
    def _compute_graph_signature(self, embedding: torch.Tensor) -> List[int]:
        """Compute LSH signature for a graph embedding"""
        embedding = embedding.to(self.device)
        if len(embedding.shape) == 1:
            embedding = embedding.unsqueeze(0)
        projections = torch.mm(embedding, self.projection_vectors.t())
        return (projections > 0).int().squeeze().tolist()
    
    def _get_band_hash(self, signature: List[int], band_idx: int) -> str:
        """Get hash value for a specific band of the signature"""
        start_idx = band_idx * self.rows_per_band
        end_idx = start_idx + self.rows_per_band
        return str(signature[start_idx:end_idx])
    
    def fit(self, dataloader: DataLoader, graph_encoder: nn.Module):
        """Fit the LSH classifier using a pre-trained graph encoder"""
        graph_encoder.eval()
        all_embeddings = []
        all_labels = []
        
        # Get embeddings for all graphs
        with torch.no_grad():
            for batch in tqdm(dataloader, desc="Computing graph embeddings"):
                batch = batch.to(self.device)
                embeddings = graph_encoder(batch)
                all_embeddings.append(embeddings)
                all_labels.extend(batch.y.cpu().numpy())
        
        # Concatenate embeddings
        all_embeddings = torch.cat(all_embeddings, dim=0)
        
        # Generate projection vectors if not already generated
        if self.projection_vectors is None:
            self._generate_projection_vectors(all_embeddings.shape[1])
        
        # Compute and store LSH signatures
        for idx, embedding in enumerate(all_embeddings):
            signature = self._compute_graph_signature(embedding)
            label = all_labels[idx]
            
            # Store in hash tables
            for band_idx in range(self.num_bands):
                band_hash = self._get_band_hash(signature, band_idx)
                self.hash_tables[band_idx][band_hash].add(idx)
            
            # Store original embedding and label
            self.graph_embeddings[idx] = embedding.cpu()
            self.graph_labels[idx] = label
    
    def predict(self, query_graph: Data, graph_encoder: nn.Module, k: int = 7) -> Tuple[int, float]:
        """Predict CWE type for a query graph"""
        graph_encoder.eval()
        
        with torch.no_grad():
            query_graph = query_graph.to(self.device)
            if not hasattr(query_graph, 'batch'):
                query_graph.batch = torch.zeros(query_graph.x.size(0), dtype=torch.long, device=self.device)
            
            query_embedding = graph_encoder(query_graph)
            query_signature = self._compute_graph_signature(query_embedding)
            
            candidates = set()
            for band_idx in range(self.num_bands):
                band_hash = self._get_band_hash(query_signature, band_idx)
                candidates.update(self.hash_tables[band_idx][band_hash])
            
            if not candidates:
                return -1, 0.0
            
            # Compute distances
            distances = []
            for idx in candidates:
                candidate_embedding = self.graph_embeddings[idx].to(self.device)
                if len(candidate_embedding.shape) == 1:
                    candidate_embedding = candidate_embedding.unsqueeze(0)
                
                dist = F.cosine_similarity(query_embedding, candidate_embedding).item()
                label = self.graph_labels[idx]
                distances.append((dist, label))
            
            distances.sort(reverse=True)
            top_k = distances[:k]
            
            # Simple voting
            vote_counts = defaultdict(float)
            for dist, label in top_k:
                similarity_weight = (1 + dist) / 2  # Convert cosine similarity to [0,1] range
                vote_counts[label] += similarity_weight
            
            predicted_cwe = max(vote_counts.items(), key=lambda x: x[1])[0]
            total_votes = sum(vote_counts.values())
            confidence = vote_counts[predicted_cwe] / total_votes if total_votes > 0 else 0.0
            
            return predicted_cwe, confidence

class GraphEncoder(nn.Module):
    """Enhanced GNN encoder with graph attention and contrastive learning"""
    def __init__(self, input_dim: int, hidden_dim: int, output_dim: int, dropout: float = 0.2):
        super().__init__()
        from torch_geometric.nn import GATConv, TransformerConv
        
        # Initial projection
        self.input_proj = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        
        # Multi-head attention layers
        self.gat1 = TransformerConv(hidden_dim, hidden_dim // 4, heads=4, dropout=dropout)
        self.gat2 = TransformerConv(hidden_dim, hidden_dim // 4, heads=4, dropout=dropout)
        self.gat3 = TransformerConv(hidden_dim, hidden_dim // 4, heads=4, dropout=dropout)
        
        # Layer norms after each attention layer
        self.ln1 = nn.LayerNorm(hidden_dim)
        self.ln2 = nn.LayerNorm(hidden_dim)
        self.ln3 = nn.LayerNorm(hidden_dim)
        
        # Final projection layers
        self.proj1 = nn.Linear(hidden_dim * 2, hidden_dim)
        self.proj2 = nn.Linear(hidden_dim, output_dim)
        
        self.dropout = nn.Dropout(dropout)
        
    def forward(self, data):
        x, edge_index = data.x, data.edge_index
        batch = data.batch if hasattr(data, 'batch') else torch.zeros(x.size(0), dtype=torch.long, device=x.device)
        
        # Initial projection
        x = self.input_proj(x)
        
        # Multi-head attention blocks with residual connections
        identity = x
        x = self.gat1(x, edge_index)
        x = self.ln1(x + identity)
        x = F.elu(x)
        x = self.dropout(x)
        
        identity = x
        x = self.gat2(x, edge_index)
        x = self.ln2(x + identity)
        x = F.elu(x)
        x = self.dropout(x)
        
        identity = x
        x = self.gat3(x, edge_index)
        x = self.ln3(x + identity)
        x = F.elu(x)
        
        # Hierarchical pooling
        cluster_scores = torch.sigmoid(x.sum(dim=-1))
        x_weighted = x * cluster_scores.unsqueeze(-1)
        
        # Global pooling with attention weights
        max_pool = global_max_pool(x_weighted, batch)
        mean_pool = global_mean_pool(x_weighted, batch)
        pooled = torch.cat([max_pool, mean_pool], dim=1)
        
        # Final projections
        out = self.proj1(pooled)
        out = F.elu(out)
        out = self.dropout(out)
        out = self.proj2(out)
        
        return F.normalize(out, p=2, dim=1)

def contrastive_loss(embeddings, labels, temperature=0.5):
    """
    Compute supervised contrastive loss
    """
    device = embeddings.device
    batch_size = embeddings.size(0)
    
    # Compute similarity matrix
    sim_matrix = torch.mm(embeddings, embeddings.t()) / temperature
    
    # Create mask for positive pairs (same class)
    labels = labels.view(-1, 1)
    mask_pos = labels == labels.t()
    mask_pos = mask_pos.float().to(device)
    
    # Remove diagonal elements
    mask_diag = torch.eye(batch_size).bool().to(device)
    mask_pos[mask_diag] = 0
    
    # Compute log-sum-exp
    logsumexp = torch.logsumexp(sim_matrix, dim=1, keepdim=True)
    
    # Compute positive terms
    pos_term = (sim_matrix * mask_pos).sum(dim=1)
    num_pos = mask_pos.sum(dim=1)
    pos_term = pos_term / (num_pos + 1e-6)
    
    # Final loss
    loss = -(pos_term - logsumexp.squeeze())
    return loss.mean()

def visualize_embeddings(embeddings, labels, save_path='embedding_visualization.png'):
    """
    Visualize the graph embeddings using t-SNE
    
    Args:
        embeddings: Graph embeddings tensor
        labels: CWE labels
        save_path: Path to save the visualization
    """
    # Convert embeddings to numpy if they're tensors
    if torch.is_tensor(embeddings):
        embeddings = embeddings.cpu().numpy()
    if torch.is_tensor(labels):
        labels = labels.cpu().numpy()
    
    # Apply t-SNE
    print("Computing t-SNE projection...")
    tsne = TSNE(n_components=2, random_state=42, perplexity=min(30, len(embeddings)-1))
    embeddings_2d = tsne.fit_transform(embeddings)
    
    # Create visualization
    plt.figure(figsize=(12, 8))
    
    # Create scatter plot with different colors for each CWE
    unique_labels = np.unique(labels)
    colors = plt.cm.rainbow(np.linspace(0, 1, len(unique_labels)))
    
    for label, color in zip(unique_labels, colors):
        mask = labels == label
        plt.scatter(
            embeddings_2d[mask, 0],
            embeddings_2d[mask, 1],
            c=[color],
            label=f'CWE-{label}',
            alpha=0.6
        )
    
    plt.title('t-SNE Visualization of Graph Embeddings')
    plt.xlabel('t-SNE Component 1')
    plt.ylabel('t-SNE Component 2')
    plt.legend(bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.tight_layout()
    plt.savefig(save_path, dpi=300, bbox_inches='tight')
    plt.close()

def train_and_evaluate(dataset: Dataset, test_size: float = 0.2, num_epochs: int = 75):
    """Train and evaluate with enhanced training strategy"""
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    
    # Split dataset
    num_samples = len(dataset)
    indices = list(range(num_samples))
    random.shuffle(indices)
    split = int(np.floor(test_size * num_samples))
    train_idx, test_idx = indices[split:], indices[:split]
    
    # Create data loaders
    train_loader = DataLoader(
        [dataset[i] for i in train_idx], 
        batch_size=32, 
        shuffle=True,
        follow_batch=['x', 'edge_index']
    )
    test_loader = DataLoader(
        [dataset[i] for i in test_idx], 
        batch_size=1,
        shuffle=False,
        follow_batch=['x', 'edge_index']
    )
    
    # Initialize models with updated parameters
    encoder = GraphEncoder(
        input_dim=dataset[0].x.shape[1],
        hidden_dim=512,
        output_dim=256,
        dropout=0.2
    ).to(device)
    
    optimizer = torch.optim.AdamW(encoder.parameters(), lr=1e-3, weight_decay=1e-4)
    scheduler = ReduceLROnPlateau(
        optimizer,
        mode='min',
        factor=0.5,
        patience=5,
        verbose=True,
        min_lr=1e-6
    )
    
    # Add early stopping
    best_loss = float('inf')
    patience_counter = 0
    patience_limit = 15
    
    def visualize_current_embeddings(encoder, dataset, device, save_path):
        encoder.eval()
        all_embeddings = []
        all_labels = []
        
        loader = DataLoader(dataset, batch_size=32, shuffle=False)
        with torch.no_grad():
            for batch in loader:
                batch = batch.to(device)
                embeddings = encoder(batch)
                all_embeddings.append(embeddings.cpu())
                all_labels.extend(batch.y.cpu().numpy())
        
        all_embeddings = torch.cat(all_embeddings, dim=0)
        visualize_embeddings(all_embeddings, all_labels, save_path)
    
    # Training loop with enhanced monitoring
    print("Training encoder with contrastive learning...")
    for epoch in range(num_epochs):
        encoder.train()
        total_loss = 0
        batch_losses = []
        
        for batch in tqdm(train_loader, desc=f"Epoch {epoch+1}/{num_epochs}"):
            batch = batch.to(device)
            optimizer.zero_grad()
            
            embeddings = encoder(batch)
            loss = contrastive_loss(embeddings, batch.y, temperature=0.07)  # Adjusted temperature
            
            loss.backward()
            torch.nn.utils.clip_grad_norm_(encoder.parameters(), 1.0)
            optimizer.step()
            
            total_loss += loss.item()
            batch_losses.append(loss.item())
        
        avg_loss = total_loss / len(train_loader)
        print(f"Epoch {epoch+1}, Loss: {avg_loss:.4f}")
        
        # Learning rate scheduling
        scheduler.step(avg_loss)
        
        # Early stopping check
        if avg_loss < best_loss:
            best_loss = avg_loss
            patience_counter = 0
            # Save best model
            torch.save(encoder.state_dict(), 'best_encoder.pt')
        else:
            patience_counter += 1
            if patience_counter >= patience_limit:
                print("Early stopping triggered!")
                # Load best model
                encoder.load_state_dict(torch.load('best_encoder.pt'))
                break
        
        # Visualize embeddings periodically
        if (epoch + 1) % 10 == 0:
            visualize_current_embeddings(encoder, dataset, device, f'embeddings_epoch_{epoch+1}.png')
    
    # Get final embeddings for LSH
    print("Computing final embeddings...")
    encoder.eval()
    all_embeddings = []
    all_labels = []
    
    with torch.no_grad():
        for batch in DataLoader(dataset, batch_size=32, shuffle=False):
            batch = batch.to(device)
            embeddings = encoder(batch)
            all_embeddings.append(embeddings.cpu())
            all_labels.extend(batch.y.cpu().numpy())
    
    all_embeddings = torch.cat(all_embeddings, dim=0)
    all_labels = np.array(all_labels)
    
    # Initialize and train LSH classifier
    classifier = LSHGraphClassifier(
        num_hash_functions=150,
        num_bands=30,
        device=device
    )
    
    # Fit classifier with final embeddings
    classifier.fit(train_loader, encoder)
    
    # Evaluate
    print("Evaluating classifier...")
    predictions = []
    true_labels = []
    confidences = []
    
    for batch in tqdm(test_loader, desc="Evaluating"):
        pred, conf = classifier.predict(batch, encoder)
        predictions.append(pred)
        true_labels.append(batch.y[0].item())
        confidences.append(conf)
    
    # Print classification report
    print("\nClassification Report:")
    print(classification_report(true_labels, predictions))
    
    # Visualize confidence distribution
    plt.figure(figsize=(10, 6))
    sns.histplot(confidences, bins=20)
    plt.title("Distribution of Prediction Confidences")
    plt.xlabel("Confidence Score")
    plt.ylabel("Count")
    plt.savefig("confidence_distribution.png")
    plt.close()
    
    return classifier, encoder, all_embeddings, all_labels

if __name__ == "__main__":
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"Using device: {device}")

    print("Loading dataset...")
    loaded_data = torch.load('juliet_dataset.pt', map_location=device)
    
    dataset = JulietDataset(
        root='data/juliet',
        dot_files=loaded_data.dot_files,
        node_embeddings=loaded_data.node_embeddings,
        node_to_idx=loaded_data.node_to_idx
    )
    
    print(f"Dataset loaded with {len(dataset)} graphs")
    
    print("Training and evaluating...")
    classifier, encoder, embeddings, labels = train_and_evaluate(dataset)
    
    # Save results
    print("Saving results...")
    torch.save({
        'encoder_state_dict': encoder.state_dict(),
        'projection_vectors': classifier.projection_vectors.cpu(),
        'hash_tables': classifier.hash_tables,
        'graph_embeddings': {k: v.cpu() for k, v in classifier.graph_embeddings.items()},
        'graph_labels': classifier.graph_labels,
        'all_embeddings': embeddings.cpu(),
        'all_labels': labels
    }, 'lsh_classifier.pt')
    
    print("Done! Check the generated visualizations:")
    print("1. initial_embeddings.png - t-SNE visualization of graph embeddings")
    print("2. confidence_distribution.png - Distribution of prediction confidences")