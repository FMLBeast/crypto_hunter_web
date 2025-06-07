# crypto_hunter_web/commands.py

import click
from flask.cli import with_appcontext

def register_commands(app):
    @app.cli.command('import-files')
    @click.argument('csv_path', type=click.Path(exists=True))
    @with_appcontext
    def import_files(csv_path):
        """Bulk-import FileNode records from a CSV."""
        from . import db
        from .importer import import_from_csv
        db.create_all()
        count = import_from_csv(csv_path)
        click.echo(f"✅ Imported {count} files from {csv_path}")

    @app.cli.command('build-graph')
    @click.option('-o', '--output', default='derivation_graph.graphml',
                  help='Path to write the GraphML file')
    @with_appcontext
    def build_graph(output):
        """Build the derivation graph and write it out as GraphML."""
        from .services.graph_builder import build_derivation_graph
        import networkx as nx

        click.echo("🔨 Building derivation graph…")
        G = build_derivation_graph()
        nx.write_graphml(G, output)
        click.echo(
            f"✅ Graph has {G.number_of_nodes()} nodes and "
            f"{G.number_of_edges()} edges, saved to {output}"
        )
