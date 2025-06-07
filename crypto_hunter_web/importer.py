from .models import FileNode
from . import db  # THIS is the SQLAlchemy instance from __init__.py
import csv

def import_from_csv(csv_path: str) -> int:
    processed = 0
    with open(csv_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            sha = row.get('sha256') or row.get('sha')
            if not sha:
                continue
            node = FileNode.query.get(sha)
            # … update or create as before …
            processed += 1
            if processed % 1000 == 0:
                db.session.commit()
        db.session.commit()
    return processed
