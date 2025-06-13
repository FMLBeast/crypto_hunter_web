#!/usr/bin/env python3
"""
Script to run LLM-orchestrated extraction on image.png
"""

import os
import sys
import logging
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    """Run LLM-orchestrated extraction on image.png"""
    logger.info("Starting LLM-orchestrated extraction on image.png")
    
    # Set environment variable to enable LLM orchestration
    os.environ['USE_LLM_ORCHESTRATOR'] = 'true'
    
    # Path to run_extraction.py
    script_path = os.path.join("crypto_hunter_web", "scripts", "run_extraction.py")
    
    # Verify script exists
    if not os.path.exists(script_path):
        logger.error(f"Script not found at {script_path}")
        return 1
    
    # Run the script with LLM orchestration enabled
    try:
        logger.info(f"Running {script_path} with LLM orchestration")
        
        # Get the path to image.png
        image_path = os.path.join("uploads", "image.png")
        if not os.path.exists(image_path):
            logger.error(f"Image not found at {image_path}")
            return 1
        
        # Run extraction with all methods
        result = subprocess.run([
            sys.executable, 
            script_path, 
            image_path, 
            "--method", "all", 
            "--output-dir", "production", 
            "--user-id", "1"
        ], check=True)
        
        logger.info("LLM-orchestrated extraction completed successfully")
        return 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running LLM-orchestrated extraction: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())