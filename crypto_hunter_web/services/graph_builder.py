# crypto_hunter_web/services/graph_builder.py

import networkx as nx
import re
from typing import Dict, List, Tuple, Optional
from crypto_hunter_web import db
from crypto_hunter_web.models import FileNode, FileDerivation


def build_derivation_graph():
    """
    Build a derivation graph from FileNode records based on naming patterns.
    Returns a networkx DiGraph where:
    - Nodes are file SHA256 hashes
    - Edges represent derivation relationships
    """
    G = nx.DiGraph()

    # Get all files from the database
    files = FileNode.query.all()
    print(f"Building graph from {len(files)} files...")

    # First pass: Add all files as nodes
    for file in files:
        G.add_node(
            file.sha256,
            path=file.path,
            description=file.description,
            file_type=file.file_type,
            mime_type=file.mime_type,
            size_bytes=file.size_bytes,
            entropy=file.entropy
        )

    # Second pass: Infer relationships based on naming patterns
    file_by_path = {f.path: f for f in files}

    for file in files:
        path = file.path

        # Pattern 1: INTERMEDIATE_xxx files derive from parent
        if 'INTERMEDIATE_' in path:
            # Extract parent SHA from filename
            match = re.search(r'INTERMEDIATE_([0-9a-f]{64})', path)
            if match:
                parent_sha = match.group(1)
                if G.has_node(parent_sha):
                    G.add_edge(parent_sha, file.sha256, relationship='intermediate')

        # Pattern 2: Files with numeric suffixes (file_1.txt, file_2.txt)
        base_match = re.match(r'(.+?)_(\d+)(\.[^.]+)?$', path)
        if base_match:
            base_name = base_match.group(1)
            number = int(base_match.group(2))
            extension = base_match.group(3) or ''

            # Look for parent (previous number)
            if number > 0:
                parent_path = f"{base_name}_{number-1}{extension}"
                if parent_path in file_by_path:
                    parent = file_by_path[parent_path]
                    G.add_edge(parent.sha256, file.sha256,
                             relationship='sequence',
                             sequence_num=number)

        # Pattern 3: image.png derivatives
        if path.startswith('image.png') and path != 'image.png':
            # Find the base image.png
            if 'image.png' in file_by_path:
                base_image = file_by_path['image.png']
                G.add_edge(base_image.sha256, file.sha256,
                         relationship='derived_from_base')

        # Pattern 4: Extract/output patterns
        if any(keyword in path.lower() for keyword in ['extract', 'output', 'result', 'decoded']):
            # Try to find the source file
            clean_name = re.sub(r'(extract|output|result|decoded)[-_]?', '', path, flags=re.IGNORECASE)
            if clean_name in file_by_path and clean_name != path:
                source = file_by_path[clean_name]
                G.add_edge(source.sha256, file.sha256, relationship='extracted')

    # Store relationships in the database
    edges_created = 0
    for parent_sha, child_sha, data in G.edges(data=True):
        # Check if relationship already exists
        existing = FileDerivation.query.filter_by(
            parent_sha=parent_sha,
            child_sha=child_sha
        ).first()

        if not existing:
            derivation = FileDerivation(
                parent_sha=parent_sha,
                child_sha=child_sha,
                operation=data.get('relationship', 'unknown'),
                confidence=0.8  # Based on naming pattern matching
            )
            db.session.add(derivation)
            edges_created += 1

    if edges_created > 0:
        db.session.commit()
        print(f"Created {edges_created} new derivation relationships")

    return G


def import_graph_from_csv(csv_path: str) -> Dict[str, any]:
    """
    Import graph relationships from CSV file.
    Expected columns: parent_sha, child_sha, operation, tool, parameters
    """
    import csv

    relationships_added = 0

    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            parent_sha = row.get('parent_sha')
            child_sha = row.get('child_sha')

            if not parent_sha or not child_sha:
                continue

            # Check both files exist
            parent = FileNode.query.get(parent_sha)
            child = FileNode.query.get(child_sha)

            if not parent or not child:
                continue

            # Check if relationship already exists
            existing = FileDerivation.query.filter_by(
                parent_sha=parent_sha,
                child_sha=child_sha
            ).first()

            if not existing:
                derivation = FileDerivation(
                    parent_sha=parent_sha,
                    child_sha=child_sha,
                    operation=row.get('operation', 'unknown'),
                    tool=row.get('tool'),
                    parameters=row.get('parameters'),
                    confidence=float(row.get('confidence', 1.0))
                )
                db.session.add(derivation)
                relationships_added += 1

    db.session.commit()

    return {
        'relationships_added': relationships_added,
        'status': 'success'
    }


def analyze_graph_structure(G: nx.DiGraph) -> Dict[str, any]:
    """Analyze the structure of the derivation graph"""

    # Find root nodes (no incoming edges)
    root_nodes = [n for n in G.nodes() if G.in_degree(n) == 0]

    # Find leaf nodes (no outgoing edges)
    leaf_nodes = [n for n in G.nodes() if G.out_degree(n) == 0]

    # Find the most connected nodes
    by_total_degree = sorted(G.nodes(), key=lambda n: G.degree(n), reverse=True)[:10]

    # Find longest paths
    longest_paths = []
    for root in root_nodes[:5]:  # Check first 5 roots to avoid taking too long
        for leaf in leaf_nodes[:5]:
            try:
                path = nx.shortest_path(G, root, leaf)
                longest_paths.append(path)
            except nx.NetworkXNoPath:
                continue

    longest_paths.sort(key=len, reverse=True)

    return {
        'total_nodes': G.number_of_nodes(),
        'total_edges': G.number_of_edges(),
        'root_nodes': len(root_nodes),
        'leaf_nodes': len(leaf_nodes),
        'most_connected': [
            {
                'sha': sha[:16] + '...',
                'in_degree': G.in_degree(sha),
                'out_degree': G.out_degree(sha),
                'total_degree': G.degree(sha)
            }
            for sha in by_total_degree
        ],
        'longest_path_length': len(longest_paths[0]) if longest_paths else 0,
        'components': nx.number_weakly_connected_components(G)
    }


# For backwards compatibility, if something is looking for GraphBuilder
GraphBuilder = build_derivation_graph