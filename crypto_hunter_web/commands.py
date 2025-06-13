# crypto_hunter_web/commands.py

import click
import networkx as nx
from networkx.readwrite.graphml import write_graphml as write_graphml_xml
from sqlalchemy.inspection import inspect

from .models import FileNode


@click.command('import-files')
@click.argument('csv_path')
def import_files(csv_path):
    """Import files from CSV into the database."""
    from .importer import import_from_csv
    count = import_from_csv(csv_path)
    click.echo(f"✅ Imported {count} files from {csv_path}")

@click.command('build-graph')
@click.option('--output', required=True, help='Where to write the .graphml')
def build_graph(output):
    """Build a derivation graph and write to GraphML."""
    click.echo("🔨 Building derivation graph…")
    G = nx.DiGraph()

    # Identify self-referential relationships on FileNode
    mapper = inspect(FileNode)
    rels = [rel for rel in mapper.relationships if rel.mapper.class_ is FileNode]

    # Build nodes and edges
    for node in FileNode.query:
        G.add_node(
            node.sha256,
            label=node.path or "",
            path=node.path or "",
            size=node.size_bytes if node.size_bytes is not None else "",
            info=node.description or ""
        )
        # Loop through each relationship to other FileNode instances
        for rel in rels:
            for child in getattr(node, rel.key) or []:
                G.add_edge(
                    node.sha256,
                    child.sha256,
                    relation=rel.key
                )

    # Sanitize None values on nodes and edges
    for _, attrs in G.nodes(data=True):
        for k, v in list(attrs.items()):
            if v is None:
                attrs[k] = ""
    for _, _, attrs in G.edges(data=True):
        for k, v in list(attrs.items()):
            if v is None:
                attrs[k] = ""

    # Write GraphML without lxml dependency
    write_graphml_xml(G, output)
    click.echo(f"✅ GraphML written to {output}")


def register_commands(app):
    """Register Flask CLI commands."""
    app.cli.add_command(import_files)
    app.cli.add_command(build_graph)
