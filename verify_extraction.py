#!/usr/bin/env python3
"""
Script to verify that extraction data is being written to the database and that relationships are being found.
"""

import os
import sys
import logging
from datetime import datetime

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Main function to verify extraction data"""
    try:
        # Import Flask app and create application context
        from crypto_hunter_web import create_app
        app = create_app()
        app.app_context().push()

        # Import necessary modules
        from crypto_hunter_web.models import (
            AnalysisFile, FileContent, Finding, ExtractionRelationship, db
        )

        # Check if there are any files in the database
        file_count = AnalysisFile.query.count()
        logger.info(f"Found {file_count} files in the database")

        if file_count == 0:
            logger.warning("No files found in the database. Run an extraction first.")
            return 1

        # Get the most recent file
        latest_file = AnalysisFile.query.order_by(AnalysisFile.created_at.desc()).first()
        logger.info(f"Latest file: {latest_file.filename} (ID: {latest_file.id})")

        # Check file content
        content_count = FileContent.query.filter_by(file_id=latest_file.id).count()
        logger.info(f"Found {content_count} content entries for file {latest_file.id}")

        if content_count > 0:
            # Get content types
            content_types = db.session.query(FileContent.content_type, db.func.count(FileContent.id)).\
                filter_by(file_id=latest_file.id).\
                group_by(FileContent.content_type).\
                all()
            
            logger.info("Content types:")
            for content_type, count in content_types:
                logger.info(f"  {content_type}: {count}")

        # Check findings
        finding_count = Finding.query.filter_by(file_id=latest_file.id).count()
        logger.info(f"Found {finding_count} findings for file {latest_file.id}")

        if finding_count > 0:
            # Get finding types
            finding_types = db.session.query(Finding.finding_type, db.func.count(Finding.id)).\
                filter_by(file_id=latest_file.id).\
                group_by(Finding.finding_type).\
                all()
            
            logger.info("Finding types:")
            for finding_type, count in finding_types:
                logger.info(f"  {finding_type}: {count}")

        # Check extraction relationships
        relationship_count = ExtractionRelationship.query.filter_by(source_file_id=latest_file.id).count()
        logger.info(f"Found {relationship_count} extraction relationships for file {latest_file.id}")

        if relationship_count > 0:
            # Get extraction methods
            extraction_methods = db.session.query(ExtractionRelationship.extraction_method, db.func.count(ExtractionRelationship.id)).\
                filter_by(source_file_id=latest_file.id).\
                group_by(ExtractionRelationship.extraction_method).\
                all()
            
            logger.info("Extraction methods:")
            for method, count in extraction_methods:
                logger.info(f"  {method}: {count}")

            # Get derived files
            derived_files = AnalysisFile.query.join(
                ExtractionRelationship, 
                ExtractionRelationship.derived_file_id == AnalysisFile.id
            ).filter(
                ExtractionRelationship.source_file_id == latest_file.id
            ).all()

            logger.info(f"Derived files ({len(derived_files)}):")
            for derived_file in derived_files:
                logger.info(f"  {derived_file.filename} (ID: {derived_file.id})")

                # Check if this file has been recursively extracted from
                recursive_count = ExtractionRelationship.query.filter_by(source_file_id=derived_file.id).count()
                if recursive_count > 0:
                    logger.info(f"    This file has {recursive_count} recursive extractions")

        # Check for advanced extraction techniques
        advanced_content = FileContent.query.filter(
            FileContent.file_id == latest_file.id,
            FileContent.extraction_method.in_(['xor_bitplanes', 'combined_bitplanes', 'dct_extract'])
        ).all()

        logger.info(f"Found {len(advanced_content)} advanced extraction content entries")
        for content in advanced_content:
            logger.info(f"  {content.extraction_method}: {content.content_size} bytes")

        # Check extraction depth
        max_depth = db.session.query(db.func.max(AnalysisFile.extraction_depth)).scalar()
        logger.info(f"Maximum extraction depth: {max_depth}")

        if max_depth > 0:
            # Count files at each depth
            depth_counts = db.session.query(AnalysisFile.extraction_depth, db.func.count(AnalysisFile.id)).\
                group_by(AnalysisFile.extraction_depth).\
                all()
            
            logger.info("Files at each depth:")
            for depth, count in depth_counts:
                logger.info(f"  Depth {depth}: {count} files")

        return 0

    except Exception as e:
        logger.error(f"Error verifying extraction data: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())