#!/usr/bin/env python3
"""
Script to run recursive extraction on image.png
"""

import os
import sys
import logging
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Run recursive extraction on image.png"""
    logger.info("Starting recursive extraction on image.png")
    
    # Path to recursive_extract.py
    script_path = os.path.join("crypto_hunter_web", "scripts", "recursive_extract.py")
    
    # Verify script exists
    if not os.path.exists(script_path):
        logger.error(f"Script not found at {script_path}")
        return 1
    
    # Run the script
    try:
        logger.info(f"Running {script_path}")
        result = subprocess.run([sys.executable, script_path], check=True)
        logger.info("Recursive extraction completed successfully")
        return 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running recursive extraction: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())