#!/usr/bin/env python3
"""
Test script for direct extraction using ExtractionEngine
"""

import json
import logging
import os
import sys
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add the current directory to the path so we can import the application
sys.path.append('.')

# Set environment variable for LLM orchestration
os.environ['USE_LLM_ORCHESTRATOR'] = 'true'
logger.info("Set USE_LLM_ORCHESTRATOR to true for testing")

try:
    # Import Flask app and create application context
    from crypto_hunter_web import create_app
    app = create_app()
    app.app_context().push()
    
    # Import necessary modules
    from crypto_hunter_web.models import AnalysisFile, db
    from crypto_hunter_web.services.extraction_engine import ExtractionEngine
    
    # Test function
    def test_extraction():
        """Test extraction with LLM orchestration"""
        logger.info("Starting extraction test")
        
        # Find a file to test
        file_path = 'uploads/image.png'
        
        # Check if file exists
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return
        
        # Get or create file record
        file_obj = AnalysisFile.query.filter_by(filepath=file_path).first()
        
        if not file_obj:
            # Create a new file record
            from crypto_hunter_web.services.file_service import FileService
            
            logger.info(f"Creating file record for {file_path}")
            file_obj = FileService.create_file_record(
                filepath=file_path,
                filename=os.path.basename(file_path),
                file_type='image/png',
                user_id=1  # System user
            )
            
            if not file_obj:
                logger.error("Failed to create file record")
                return
        
        # Perform extraction
        logger.info(f"Performing extraction on file: {file_obj.filename} (ID: {file_obj.id})")
        
        extraction_method = 'zsteg'
        parameters = {}
        
        start_time = time.time()
        
        result = ExtractionEngine.extract_from_file(
            source_file=file_obj,
            extraction_method=extraction_method,
            parameters=parameters,
            user_id=1  # System user
        )
        
        elapsed_time = time.time() - start_time
        
        # Log results
        logger.info(f"Extraction completed in {elapsed_time:.2f} seconds")
        logger.info(f"Result: {json.dumps(result, indent=2, default=str)}")
        
        # If the extraction is asynchronous, wait for it to complete
        if result.get('is_async'):
            task_id = result.get('task_id')
            logger.info(f"Extraction is asynchronous. Task ID: {task_id}")
            
            # Wait for the task to complete
            max_wait = 120  # seconds
            start_time = time.time()
            
            while time.time() - start_time < max_wait:
                # Check task status
                from crypto_hunter_web.services.background_service import BackgroundService
                status = BackgroundService.get_task_status(task_id)
                
                logger.info(f"Task status: {status.get('state')}")
                
                if status.get('state') in ['SUCCESS', 'FAILURE']:
                    logger.info(f"Task completed with result: {json.dumps(status.get('result'), indent=2, default=str)}")
                    break
                
                # Wait a bit before checking again
                time.sleep(5)
            
            if time.time() - start_time >= max_wait:
                logger.error(f"Task did not complete in {max_wait} seconds")
        
        return result
    
    # Run the test
    test_result = test_extraction()
    
    # Print summary
    print("\n" + "="*50)
    print("EXTRACTION TEST SUMMARY")
    print("="*50)
    
    if test_result:
        print(f"Success: {test_result.get('success', False)}")
        print(f"Message: {test_result.get('message', 'N/A')}")
        
        if test_result.get('is_async'):
            print(f"Task ID: {test_result.get('task_id', 'N/A')}")
        elif test_result.get('success'):
            print(f"Extracted file: {test_result.get('extracted_file').filename if test_result.get('extracted_file') else 'N/A'}")
        else:
            print(f"Error: {test_result.get('error', 'Unknown error')}")
            print(f"Details: {test_result.get('details', 'No details')}")
    else:
        print("No result returned from test")
    
    print("="*50)

except Exception as e:
    logger.error(f"Error during test: {e}", exc_info=True)
    print(f"Error: {e}")

finally:
    # Reset environment variable
    os.environ['USE_LLM_ORCHESTRATOR'] = 'false'
    logger.info("Reset USE_LLM_ORCHESTRATOR to false")