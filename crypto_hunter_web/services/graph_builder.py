"""
GraphBuilder: constructs a directed derivation graph of files for the puzzle.
"""
import csv
import networkx as nx
import click
from flask.cli import with_appcontext
from typing import Dict, Any, List
from crypto_hunter_web.models import AnalysisFile, FileDerivation
from crypto_hunter_web import db

class GraphBuilder:
    """Builds and persists a file derivation graph using NetworkX and the DB."""

    @staticmethod
    def parse_csv(csv_path: str) -> List[Dict[str, Any]]:
        """Read CSV rows into dicts with sha, parent_sha, metadata."""
        rows = []
        with open(csv_path, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append({
                    'sha': row.get('sha256') or row.get('sha'),
                    'parent_sha': row.get('parent_sha'),
                    'path': row.get('path'),
                    'description': row.get('description')
                })
        return rows

    @staticmethod
    def build_graph(rows: List[Dict[str, Any]]) -> nx.DiGraph:
        """Construct a NetworkX graph from parsed CSV data."""
        g = nx.DiGraph()
        for r in rows:
            g.add_node(r['sha'], path=r['path'], description=r.get('description'))
        for r in rows:
            parent = r.get('parent_sha')
            if parent and g.has_node(parent):
                g.add_edge(parent, r['sha'])
        return g

    @staticmethod
    def persist_graph(graph: nx.DiGraph) -> None:
        """Save edges to FileDerivation table."""
        FileDerivation.query.delete()
        db.session.flush()
        for parent, child in graph.edges():
            db.session.add(FileDerivation(parent_sha=parent, child_sha=child))
        db.session.commit()

    @classmethod
    def import_from_csv_and_build(cls, csv_path: str) -> None:
        """Full pipeline: parse CSV, build graph, persist to DB."""
        rows = cls.parse_csv(csv_path)
        graph = cls.build_graph(rows)
        cls.persist_graph(graph)


@click.command('import-graph')
@with_appcontext
@click.argument('csv_path', default='file_report.csv')
def import_graph(csv_path: str) -> None:
    """CLI command: build derivation graph from CSV and commit."""
    GraphBuilder.import_from_csv_and_build(csv_path)
    click.echo(
        f"Imported graph from {csv_path} and persisted "
        f"{len(GraphBuilder.build_graph(GraphBuilder.parse_csv(csv_path)).edges())} edges."
    )
