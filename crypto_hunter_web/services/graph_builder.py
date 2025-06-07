# crypto_hunter_web/services/graph_builder.py

import networkx as nx
from crypto_hunter_web import db
from crypto_hunter_web.models import FileNode, FileDerivation

def build_derivation_graph():
    """
    Queries FileNode and FileDerivation tables and returns
    a networkx.DiGraph where:
      - each node is a FileNode.sha256
      - node attrs include path, description, file_type, mime_type, size_bytes
      - each edge is parent→child with attrs operation, tool, parameters
    """
    G = nx.DiGraph()

    # 1) Add every file as a node
    for f in FileNode.query:
        G.add_node(
            f.sha256,
            path=f.path,
            description=f.description,
            file_type=f.file_type,
            mime_type=f.mime_type,
            size_bytes=f.size_bytes
        )

    # 2) Add derivation edges
    for d in FileDerivation.query:
        # adjust these attribute names if yours differ
        parent = d.parent_sha
        child  = d.child_sha

        G.add_edge(
            parent,
            child,
            operation=getattr(d, 'operation', None),
            tool     =getattr(d, 'tool', None),
            parameters=getattr(d, 'parameters', None)
        )

    return G
