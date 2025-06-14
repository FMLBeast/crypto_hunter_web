#!/usr/bin/env python3
"""
Script to run extraction tasks from the command line
"""

import os
import sys
import argparse
import logging
from datetime import datetime

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Main function to parse arguments and run extraction tasks"""
    parser = argparse.ArgumentParser(description='Run extraction tasks on files')

    # Required arguments
    parser.add_argument('file_path', help='Path to the file to extract from')

    # Optional arguments
    parser.add_argument('--method', '-m', default='all', 
                        help='Extraction method to use (default: all)')
    parser.add_argument('--output-dir', '-o', default='production',
                        help='Directory to save extracted files (default: production)')
    parser.add_argument('--user-id', '-u', type=int, default=1,
                        help='User ID to attribute the extraction to (default: 1)')
    parser.add_argument('--background', '-b', action='store_true',
                        help='Run extraction in the background using Celery')
    parser.add_argument('--wait', '-w', action='store_true',
                        help='Wait for background task to complete')
    parser.add_argument('--parameters', '-p', default='{}',
                        help='JSON string of parameters for the extraction method')

    args = parser.parse_args()

    # Verify file exists
    if not os.path.exists(args.file_path):
        logger.error(f"File not found: {args.file_path}")
        return 1

    try:
        # Import Flask app and create application context
        from crypto_hunter_web import create_app
        app = create_app()
        app.app_context().push()

        # Import necessary modules
        from crypto_hunter_web.models import AnalysisFile, db
        from crypto_hunter_web.services.file_service import FileService
        from crypto_hunter_web.services.extraction import ExtractionService

        # Get or create file record
        file_obj = AnalysisFile.query.filter_by(filepath=args.file_path).first()

        if not file_obj:
            # Create a new file record
            logger.info(f"Creating file record for {args.file_path}")

            # Get file info
            file_size = os.path.getsize(args.file_path)
            file_name = os.path.basename(args.file_path)

            # Determine file type
            import magic
            file_type = magic.from_file(args.file_path, mime=True)

            # Create file record
            file_obj = FileService.create_file_record(
                filepath=args.file_path,
                filename=file_name,
                file_size=file_size,
                file_type=file_type,
                user_id=args.user_id
            )

            if not file_obj:
                logger.error("Failed to create file record")
                return 1

        # Parse parameters if provided
        import json
        parameters = json.loads(args.parameters) if args.parameters else {}

        # Run extraction
        logger.info(f"Running extraction: {args.method} (async: {args.background})")

        if args.method == 'all':
            # Run all methods
            result = ExtractionService.extract_all_methods(
                file_id=file_obj.id,
                user_id=args.user_id,
                async_mode=args.background
            )
        elif args.method == 'production':
            # Run production extraction
            result = ExtractionService.extract_to_production(
                file_id=file_obj.id,
                output_dir=args.output_dir,
                user_id=args.user_id,
                async_mode=args.background
            )
        else:
            # Run specific method
            result = ExtractionService.extract_from_file(
                file_id=file_obj.id,
                extraction_method=args.method,
                parameters=parameters,
                user_id=args.user_id,
                async_mode=args.background
            )

        # Log result
        if result.get('is_async', False):
            logger.info(f"Task ID: {result.get('task_id')}")
            logger.info(f"Message: {result.get('message')}")

            # Wait for task to complete if requested
            if args.wait:
                logger.info("Waiting for task to complete...")
                task_id = result.get('task_id')

                # Import Celery task
                from celery.result import AsyncResult
                from crypto_hunter_web.services.celery_app import celery_app

                # Get task result
                task = AsyncResult(task_id, app=celery_app)
                task_result = task.get()

                logger.info(f"Task completed: {task_result}")
        else:
            logger.info(f"Extraction completed: {result}")

        return 0

    except Exception as e:
        logger.error(f"Error during extraction: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())
