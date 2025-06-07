#!/usr/bin/env python3
"""
One‑step script to add `description` column if missing and import CSV into your DB.
Usage:
    python migrate_and_import.py [path/to/file_report.csv]
"""
import os
import csv
from datetime import datetime
from sqlalchemy import create_engine, inspect, text, Column, String, Integer, Float, DateTime, MetaData
from sqlalchemy.orm import declarative_base, sessionmaker

# --- Configuration ---
DB_URL = os.getenv('DATABASE_URL', 'sqlite:///arweave_tracker.db')
CSV_FILE = os.path.abspath(os.getenv('CSV_PATH', 'file_report.csv'))

# --- Setup engine & session ---
engine = create_engine(DB_URL)
Session = sessionmaker(bind=engine)
session = Session()

# --- Ensure `description` column exists ---
inspector = inspect(engine)
if 'file_nodes' in inspector.get_table_names():
    cols = [c['name'] for c in inspector.get_columns('file_nodes')]
    if 'description' not in cols:
        print('Adding `description` column to file_nodes...')
        engine.execute(text('ALTER TABLE file_nodes ADD COLUMN description VARCHAR'))
    else:
        print('`description` column already exists.')
else:
    raise RuntimeError('Table `file_nodes` not found in database.')

# --- Define ORM model reflecting updated table ---
Base = declarative_base(metadata=MetaData(bind=engine))
class FileNode(Base):
    __tablename__ = 'file_nodes'
    sha256           = Column(String(64), primary_key=True)
    path             = Column(String, nullable=False)
    description      = Column(String)
    file_type        = Column(String)
    mime_type        = Column(String)
    size_bytes       = Column(Integer)
    creation_date    = Column(DateTime)
    modification_date= Column(DateTime)
    entropy          = Column(Float)
    imported_at      = Column(DateTime, default=datetime.utcnow)

# --- Parse CSV and upsert ---
if not os.path.exists(CSV_FILE):
    raise FileNotFoundError(f'CSV file not found: {CSV_FILE}')

count_new = 0
count_upd = 0
with open(CSV_FILE, newline='') as f:
    reader = csv.DictReader(f)
    for row in reader:
        sha = row['sha256']
        node = session.query(FileNode).get(sha)
        desc = row.get('description') or None
        if node:
            if desc and node.description != desc:
                node.description = desc
                count_upd += 1
        else:
            node = FileNode(
                sha256=sha,
                path=row['path'],
                description=desc,
                file_type=row.get('file_type'),
                mime_type=row.get('mime_type'),
                size_bytes=int(row.get('size_bytes', 0)),
                creation_date=datetime.fromisoformat(row['creation_date']),
                modification_date=datetime.fromisoformat(row['modification_date']),
                entropy=float(row.get('entropy', 0.0)),
            )
            session.add(node)
            count_new += 1
session.commit()
print(f'Imported {count_new} new records, updated {count_upd} descriptions.')
