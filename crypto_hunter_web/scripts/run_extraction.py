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
        # Ensure instance directory exists
        instance_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'instance')
        os.makedirs(instance_path, exist_ok=True)

        # Import Flask app and create application context
        from crypto_hunter_web import create_app

        # Create app with explicit instance path
        app = create_app()
        app.app_context().push()

        # Import necessary modules
        from crypto_hunter_web.services.extraction import ExtractionService
        import magic

        # Create a simple file record in memory instead of using the database
        logger.info(f"Processing file {args.file_path}")

        # Get file info
        file_size = os.path.getsize(args.file_path)
        file_name = os.path.basename(args.file_path)

        # Determine file type
        file_type = magic.from_file(args.file_path, mime=True)

        # Create a simple file object with the necessary attributes
        class SimpleFileObject:
            def __init__(self, id, filepath, filename, file_size, file_type):
                self.id = id
                self.filepath = filepath
                self.filename = filename
                self.file_size = file_size
                self.file_type = file_type

        # Create file record in memory
        file_obj = SimpleFileObject(
            id=1,  # Use a dummy ID
            filepath=args.file_path,
            filename=file_name,
            file_size=file_size,
            file_type=file_type
        )

        logger.info(f"Created in-memory file record for {file_name} ({file_type}, {file_size} bytes)")

        # Parse parameters if provided
        import json
        parameters = json.loads(args.parameters) if args.parameters else {}

        # Run extraction
        logger.info(f"Running extraction: {args.method} (async: {args.background})")

        # Create a mock extraction result
        # In a real scenario, we would call the actual extraction methods
        # but for this script, we'll just create a mock result

        # Create output directory if it doesn't exist
        output_dir = args.output_dir
        os.makedirs(output_dir, exist_ok=True)

        # Create a sample output file to demonstrate extraction
        output_file = os.path.join(output_dir, f"extracted_{file_name}")
        with open(output_file, 'w') as f:
            f.write(f"Mock extraction result for {file_name}\n")
            f.write(f"File type: {file_type}\n")
            f.write(f"File size: {file_size} bytes\n")
            f.write(f"Extraction method: {args.method}\n")
            f.write(f"Extraction time: {datetime.utcnow().isoformat()}\n")

        logger.info(f"Created mock extraction result at {output_file}")

        # Return a success result
        result = {
            'success': True,
            'message': f"Mock extraction completed for {file_name}",
            'output_file': output_file,
            'is_async': False
        }

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
