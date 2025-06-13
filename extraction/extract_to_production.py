#!/usr/bin/env python3
"""
Simple script to extract files from a specified file into the production directory.
This script uses the extractors directly without database dependency.
"""

import argparse
import logging
import os
import shutil
import sys

# Add parent directory to path to allow imports
sys.path.append('.')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Import extractors
from crypto_hunter_web.services.extractors import get_extractor

# Constants
DEFAULT_IMAGE_PATH = "uploads/image.png"
DEFAULT_OUTPUT_DIR = "production"

# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(description='Extract files from a specified file into the production directory')
    parser.add_argument('file_path', nargs='?', default=DEFAULT_IMAGE_PATH, 
                        help='Path to the file to extract from (default: uploads/image.png)')
    parser.add_argument('--output-dir', '-o', default=DEFAULT_OUTPUT_DIR,
                        help='Directory to save extraction results (default: production)')
    return parser.parse_args()

def main():
    """Main function to extract files from a specified file into production directory"""
    # Parse command line arguments
    args = parse_args()
    file_path = args.file_path
    output_dir = args.output_dir

    logger.info(f"Starting extraction from {file_path} into {output_dir} directory")

    # Verify the file exists
    if not os.path.exists(file_path):
        logger.error(f"File not found at {file_path}")
        return

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Copy the original file to the output directory and mark it as root
    file_name = os.path.basename(file_path)
    root_file_path = os.path.join(output_dir, file_name)
    shutil.copy2(file_path, root_file_path)
    logger.info(f"Copied {file_path} to {root_file_path} (marked as root)")

    # Run extractors
    run_extractors(file_path, output_dir)

    logger.info("Extraction complete!")

def run_extractors(file_path: str, output_dir: str):
    """Run extractors on the image and save extracted files to output directory"""
    # List of extractors to use
    extractors = ['zsteg', 'binwalk', 'foremost', 'steghide']

    for extractor_name in extractors:
        try:
            logger.info(f"Running {extractor_name} extractor")

            # Get extractor
            extractor = get_extractor(extractor_name)
            if not extractor:
                logger.warning(f"Extractor {extractor_name} not found")
                continue

            # Create extractor-specific output directory
            extractor_output_dir = os.path.join(output_dir, f"{extractor_name}_extracted")
            os.makedirs(extractor_output_dir, exist_ok=True)

            # Run extraction with output directory parameter
            result = extractor.extract(file_path, {'output_dir': extractor_output_dir})

            # Log results
            logger.info(f"{extractor_name} extraction result: {result['success']}")
            logger.info(f"{extractor_name} extraction details: {result['details']}")

            # If extraction was successful and data was found
            if result['success'] and result['data']:
                logger.info(f"Extracted data size: {len(result['data'])} bytes")

                # Save extracted data to file if it's not empty
                if result['data']:
                    data_file_path = os.path.join(extractor_output_dir, f"{extractor_name}_data.bin")
                    with open(data_file_path, 'wb') as f:
                        f.write(result['data'])
                    logger.info(f"Saved extracted data to {data_file_path}")

                # Process metadata if available
                if 'metadata' in result and 'extracted_files' in result['metadata']:
                    files = result['metadata']['extracted_files']
                    logger.info(f"Extracted {len(files)} files")

                    # Copy extracted files to output directory if they exist
                    for file_info in files:
                        if 'path' in file_info and os.path.exists(file_info['path']):
                            dest_path = os.path.join(extractor_output_dir, os.path.basename(file_info['path']))
                            shutil.copy2(file_info['path'], dest_path)
                            logger.info(f"Copied extracted file from {file_info['path']} to {dest_path}")

            logger.info(f"{extractor_name} extraction complete")

        except Exception as e:
            logger.error(f"Error running {extractor_name}: {str(e)}")

if __name__ == "__main__":
    main()
