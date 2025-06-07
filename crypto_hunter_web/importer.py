# crypto_hunter_web/importer.py

import csv
from .models import FileNode
from . import db


def import_from_csv(csv_path: str) -> int:
    """
    Bulk‐import FileNode records from a CSV file,
    committing every BATCH_SIZE rows, and skipping duplicate SHAs.
    Returns total rows processed.
    """
    BATCH_SIZE = 1000
    processed = 0
    imported = 0
    updated = 0
    new_nodes = []
    seen_shas = set()

    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            sha = row.get('sha256') or row.get('sha256_hash') or row.get('sha')
            if not sha or sha in seen_shas:
                # either missing or duplicate within this run
                continue

            processed += 1
            seen_shas.add(sha)

            existing = (
                db.session.query(FileNode)
                .filter_by(sha256=sha)
                .first()
            )

            if not existing:
                node = FileNode(
                    sha256=sha,
                    path=row.get('path') or row.get('filename') or row.get('file_path') or '',
                    description=row.get('description'),
                    file_type=row.get('file_type'),
                    mime_type=row.get('mime_type'),
                    size_bytes=(
                        int(row.get('size_bytes') or row.get('size') or 0)
                        if (row.get('size_bytes') or row.get('size'))
                        else None
                    ),
                    entropy=(
                        float(row.get('entropy'))
                        if row.get('entropy') else None
                    )
                )
                new_nodes.append(node)
                imported += 1
            else:
                changed = False
                desc = row.get('description')
                ft   = row.get('file_type')
                if desc and not existing.description:
                    existing.description = desc
                    changed = True
                if ft and not existing.file_type:
                    existing.file_type = ft
                    changed = True
                if changed:
                    updated += 1

            # every BATCH_SIZE new SHAs, flush + commit
            if len(seen_shas) % BATCH_SIZE == 0:
                if new_nodes:
                    db.session.add_all(new_nodes)
                    new_nodes.clear()
                db.session.commit()
                seen_shas.clear()  # reset so next batch can track duplicates
                print(f"Processed {processed:,} rows — imported {imported:,}, updated {updated:,}")

    # final commit for leftovers
    if new_nodes:
        db.session.add_all(new_nodes)
    db.session.commit()
    print(f"Import complete: {processed:,} rows processed, {imported:,} imported, {updated:,} updated.")

    return processed
