#!/usr/bin/env python3
"""
Orchestrator script for production extraction
This script coordinates the extraction process, ensuring all tools are available
and running the extraction with all available extractors.
"""

import argparse
import logging
import os
import subprocess
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add parent directory to path to allow imports
sys.path.append('.')

# Constants
DEFAULT_IMAGE_PATH = "uploads/image.png"
OUTPUT_DIR = "production"
REQUIRED_TOOLS = ['zsteg', 'binwalk', 'foremost', 'steghide', 'exiftool']
EXTRACTORS = ['zsteg', 'binwalk', 'foremost', 'steghide']
USE_AI_ORCHESTRATOR = os.environ.get('USE_LLM_ORCHESTRATOR', 'true').lower() in ('true', '1', 'yes')

# Parse command line arguments
def parse_args():
    parser = argparse.ArgumentParser(description='Run extraction on a file using all available extractors')
    parser.add_argument('file_path', nargs='?', default=DEFAULT_IMAGE_PATH, 
                        help='Path to the file to extract from (default: uploads/image.png)')
    parser.add_argument('--output-dir', '-o', default=OUTPUT_DIR,
                        help='Directory to save extraction results (default: production)')
    parser.add_argument('--use-ai', '-a', action='store_true', default=USE_AI_ORCHESTRATOR,
                        help='Use AI orchestrator for extraction (default: True)')
    parser.add_argument('--no-ai', '-n', action='store_false', dest='use_ai',
                        help='Disable AI orchestrator for extraction')
    return parser.parse_args()

def check_tools_installed():
    """Check if all required tools are installed"""
    missing_tools = []

    # First check with 'which' command
    for tool in REQUIRED_TOOLS:
        try:
            result = subprocess.run(['which', tool], capture_output=True, text=True)
            if result.returncode != 0:
                missing_tools.append(tool)
                logger.warning(f"Tool not found in PATH: {tool}")
        except Exception as e:
            logger.error(f"Error checking for {tool}: {e}")
            missing_tools.append(tool)

    # Then check with extractor's is_available method
    if not missing_tools:
        try:
            from crypto_hunter_web.services.extractors import get_extractor

            for tool_name in EXTRACTORS:
                extractor = get_extractor(tool_name)
                if extractor and not extractor.is_available():
                    logger.warning(f"Tool not available according to extractor: {tool_name}")
                    missing_tools.append(tool_name)
        except Exception as e:
            logger.error(f"Error checking extractor availability: {e}")

    return missing_tools

def install_missing_tools(missing_tools):
    """Install missing tools using the install_tools.py script"""
    if not missing_tools:
        return True

    logger.info(f"Installing missing tools: {', '.join(missing_tools)}")

    try:
        # Check if we have sudo access
        result = subprocess.run(['sudo', '-n', 'true'], capture_output=True, text=True)
        has_sudo = result.returncode == 0

        if has_sudo:
            cmd = ['sudo', './install_tools.py']
        else:
            logger.warning("No sudo access. Will try to run install_tools.py directly.")
            cmd = ['./install_tools.py']

        result = subprocess.run(cmd, capture_output=True, text=True)

        if result.returncode == 0:
            logger.info("Tools installation successful")
            return True
        else:
            logger.error(f"Tools installation failed: {result.stderr}")
            return False

    except Exception as e:
        logger.error(f"Error installing tools: {e}")
        return False

def prepare_directories():
    """Prepare directories for extraction"""
    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Create extractor-specific output directories
    for extractor in EXTRACTORS:
        extractor_dir = os.path.join(OUTPUT_DIR, f"{extractor}_extracted")
        os.makedirs(extractor_dir, exist_ok=True)

    # Copy the original file to the output directory and mark it as root
    import shutil
    root_file_path = os.path.join(OUTPUT_DIR, "image.png")
    if not os.path.exists(root_file_path):
        shutil.copy2(IMAGE_PATH, root_file_path)
        logger.info(f"Copied {IMAGE_PATH} to {root_file_path} (marked as root)")

def run_extraction_with_ai_orchestrator():
    """Run extraction using the AI orchestrator"""
    logger.info("Using AI orchestrator for extraction")

    try:
        # Import here to avoid circular imports
        from crypto_hunter_web.services.llm_crypto_orchestrator import LLMCryptoOrchestrator
        from crypto_hunter_web.models import AnalysisFile

        # Get or create file record
        file_obj = None
        try:
            from crypto_hunter_web.models import db
            file_obj = AnalysisFile.query.filter_by(filepath=IMAGE_PATH).first()

            if not file_obj:
                # Create a new file record
                logger.info(f"Creating file record for {IMAGE_PATH}")

                # Get file info
                file_size = os.path.getsize(IMAGE_PATH)
                file_name = os.path.basename(IMAGE_PATH)

                # Determine file type
                import magic
                file_type = magic.from_file(IMAGE_PATH, mime=True)

                # Create file record
                file_obj = AnalysisFile(
                    filepath=IMAGE_PATH,
                    filename=file_name,
                    file_size=file_size,
                    file_type=file_type,
                    status='pending'
                )

                db.session.add(file_obj)
                db.session.commit()
        except Exception as e:
            logger.warning(f"Error creating file record: {e}")
            logger.info("Continuing without file record")

        # Initialize the orchestrator
        orchestrator = LLMCryptoOrchestrator()

        # Run orchestrated analysis for each extractor
        results = {}
        for extractor_name in EXTRACTORS:
            try:
                logger.info(f"Running AI-orchestrated extraction with {extractor_name}")

                # Create extractor-specific output directory
                extractor_output_dir = os.path.join(OUTPUT_DIR, f"{extractor_name}_extracted")

                # Parameters for extraction
                parameters = {
                    'output_dir': extractor_output_dir
                }

                # Run orchestrated extraction
                if file_obj:
                    # Use file_id if we have a file record
                    result = orchestrator.llm_orchestrated_analysis(
                        file_obj.id,
                        extraction_method=extractor_name,
                        parameters=parameters,
                        force_reanalysis=True
                    )
                else:
                    # Use direct content extraction if no file record
                    with open(IMAGE_PATH, 'rb') as f:
                        content = f.read()

                    # Get a preview of the content
                    content_preview = content[:4096].hex()

                    result = orchestrator.extract_with_llm(
                        None,  # No file_id
                        content_preview,
                        extractor_name,
                        parameters
                    )

                # Process result
                if isinstance(result, dict) and result.get('success', False):
                    logger.info(f"AI-orchestrated extraction with {extractor_name} succeeded")
                    results[extractor_name] = {
                        'success': True,
                        'details': result.get('details', 'AI-orchestrated extraction succeeded'),
                        'confidence': result.get('confidence', 0.8),
                        'data': result.get('data', b'')
                    }
                else:
                    logger.warning(f"AI-orchestrated extraction with {extractor_name} failed")
                    results[extractor_name] = {
                        'success': False,
                        'error': 'AI-orchestrated extraction failed',
                        'details': str(result)
                    }
            except Exception as e:
                logger.error(f"Error running AI-orchestrated extraction with {extractor_name}: {e}")
                results[extractor_name] = {
                    'success': False,
                    'error': str(e)
                }

        return results
    except Exception as e:
        logger.error(f"Error in AI-orchestrated extraction: {e}")
        logger.info("Falling back to manual extraction")
        return run_extraction_manual()

def run_extraction_manual():
    """Run extraction using all available extractors manually"""
    from crypto_hunter_web.services.extractors import get_extractor

    results = {}

    for extractor_name in EXTRACTORS:
        try:
            logger.info(f"Running {extractor_name} extractor")

            # Get extractor
            extractor = get_extractor(extractor_name)
            if not extractor:
                logger.warning(f"Extractor {extractor_name} not found")
                continue

            # Check if extractor is available
            if not extractor.is_available():
                logger.warning(f"Extractor {extractor_name} is not available")
                continue

            # Create extractor-specific output directory
            extractor_output_dir = os.path.join(OUTPUT_DIR, f"{extractor_name}_extracted")

            # Run extraction with output directory parameter
            result = extractor.extract(IMAGE_PATH, {'output_dir': extractor_output_dir})

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
                            import shutil
                            shutil.copy2(file_info['path'], dest_path)
                            logger.info(f"Copied extracted file from {file_info['path']} to {dest_path}")

            results[extractor_name] = result
            logger.info(f"{extractor_name} extraction complete")

        except Exception as e:
            logger.error(f"Error running {extractor_name}: {str(e)}")
            results[extractor_name] = {'success': False, 'error': str(e)}

    return results

def verify_extraction(results):
    """Verify that extraction was successful"""
    success_count = sum(1 for result in results.values() if result.get('success', False))

    logger.info(f"Extraction complete. {success_count} out of {len(results)} extractors succeeded.")

    # Check if any extractor succeeded
    if success_count > 0:
        logger.info("Extraction was successful!")
        return True
    else:
        logger.error("All extractors failed!")
        return False

def print_summary(results):
    """Print summary of extraction results"""
    print("\n" + "="*50)
    print("EXTRACTION SUMMARY")
    print("="*50)

    for extractor_name, result in results.items():
        print(f"\n{extractor_name.upper()}:")
        print(f"  Success: {result.get('success', False)}")

        if result.get('success', False):
            print(f"  Details: {result.get('details', 'N/A')}")
            print(f"  Confidence: {result.get('confidence', 0)}")

            if 'data' in result and result['data']:
                print(f"  Extracted data size: {len(result['data'])} bytes")

            if 'metadata' in result and 'extracted_files' in result['metadata']:
                files = result['metadata']['extracted_files']
                print(f"  Extracted files: {len(files)}")
        else:
            print(f"  Error: {result.get('error', 'Unknown error')}")

    print("\n" + "="*50)

def main():
    """Main function to orchestrate the extraction process"""
    # Parse command line arguments
    args = parse_args()
    image_path = args.file_path
    output_dir = args.output_dir
    use_ai = args.use_ai

    logger.info(f"Starting extraction orchestration on {image_path}")
    logger.info(f"Output directory: {output_dir}")
    logger.info(f"Using AI orchestrator: {use_ai}")

    # Check if image exists
    if not os.path.exists(image_path):
        logger.error(f"File not found at {image_path}")
        return False

    # Update global variables for this run
    global IMAGE_PATH, OUTPUT_DIR
    IMAGE_PATH = image_path
    OUTPUT_DIR = output_dir

    # Check if required tools are installed
    missing_tools = check_tools_installed()
    if missing_tools:
        logger.warning(f"Missing tools: {', '.join(missing_tools)}")

        # Try to install missing tools
        if not install_missing_tools(missing_tools):
            logger.error("Failed to install missing tools. Please install them manually.")
            logger.info("You can run: sudo ./install_tools.py")
            return False

    # Prepare directories
    prepare_directories()

    # Initialize Flask app context if needed
    try:
        from crypto_hunter_web import create_app
        app = create_app()
        app.app_context().push()
        logger.info("Flask app context initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize Flask app context: {e}")
        logger.info("Continuing without Flask app context")

    # Run extraction with AI orchestrator if enabled
    if use_ai:
        logger.info("Using AI orchestrator for extraction")
        results = run_extraction_with_ai_orchestrator()
    else:
        logger.info("Using manual extraction")
        results = run_extraction_manual()

    # Verify extraction
    success = verify_extraction(results)

    # Print summary
    print_summary(results)

    return success

def test_ai_orchestrator():
    """Test the AI orchestrator"""
    logger.info("Testing AI orchestrator")

    # Set environment variable to enable AI orchestrator
    os.environ['USE_LLM_ORCHESTRATOR'] = 'true'

    # Create a test file
    test_file = os.path.join(os.getcwd(), 'test_image.png')
    if not os.path.exists(test_file):
        # Create a simple PNG file
        try:
            from PIL import Image
            img = Image.new('RGB', (100, 100), color = 'red')
            img.save(test_file)
            logger.info(f"Created test file: {test_file}")
        except ImportError:
            logger.warning("PIL not installed, using a sample file instead")
            # Copy a sample file if available
            sample_files = [
                os.path.join(os.getcwd(), 'uploads', 'image.png'),
                '/tmp/image.png'
            ]
            for sample in sample_files:
                if os.path.exists(sample):
                    import shutil
                    shutil.copy2(sample, test_file)
                    logger.info(f"Copied sample file to: {test_file}")
                    break
            else:
                logger.error("No sample file available for testing")
                return False

    # Set up test parameters
    global IMAGE_PATH, OUTPUT_DIR
    IMAGE_PATH = test_file
    OUTPUT_DIR = os.path.join(os.getcwd(), 'test_output')

    # Prepare directories
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Initialize Flask app context if needed
    try:
        from crypto_hunter_web import create_app
        app = create_app()
        app.app_context().push()
        logger.info("Flask app context initialized")
    except Exception as e:
        logger.warning(f"Failed to initialize Flask app context: {e}")
        logger.info("Continuing without Flask app context")

    # Run extraction with AI orchestrator
    results = run_extraction_with_ai_orchestrator()

    # Verify extraction
    success = verify_extraction(results)

    # Print summary
    print_summary(results)

    logger.info(f"AI orchestrator test {'succeeded' if success else 'failed'}")
    return success

if __name__ == "__main__":
    # Check if we're running a test
    if len(sys.argv) > 1 and sys.argv[1] == '--test-ai':
        sys.exit(0 if test_ai_orchestrator() else 1)
    else:
        sys.exit(0 if main() else 1)
