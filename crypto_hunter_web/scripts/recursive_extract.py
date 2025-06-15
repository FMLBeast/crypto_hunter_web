"""
Recursive steganography and file carving script for image.png
This script extracts all hidden data from image.png, saves it to the filesystem,
and recursively analyzes any extracted files for further hidden data.

DEPRECATED: This script is deprecated and will be removed in a future version.
Please use the new LLM Orchestrated Recursive Extraction system instead:
    python run_llm_extraction.py
The new system combines LLM orchestration with recursive extraction for better results.
"""

import os
import sys
import logging
import subprocess
import shutil
import tempfile
import magic
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Set, Tuple

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import Flask app and database models
from crypto_hunter_web import create_app
from crypto_hunter_web.extensions import db
from crypto_hunter_web.models import (
    AnalysisFile, FileContent, Finding, ExtractionRelationship,
    FileNode, GraphEdge, FileStatus
)
from crypto_hunter_web.services.extractors import (
    analyze_png_file, extract_png_metadata, get_extractor
)
from crypto_hunter_web.services.extraction_engine import ExtractionEngine

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
IMAGE_PATH = "uploads/image.png"
OUTPUT_DIR = "production"
MAX_DEPTH = 10  # Maximum recursion depth
PROCESSED_FILES = set()  # Keep track of processed files by hash
ADMIN_USER_ID = 1  # Admin user ID for attribution
DB_FILE_RECORDS = {}  # Cache of file records by hash

def get_or_create_file_record(file_path: str) -> AnalysisFile:
    """Get or create a file record in the database"""
    # Calculate file hash
    file_hash = calculate_file_hash(file_path)

    # Check if we already have this file in our cache
    if file_hash in DB_FILE_RECORDS:
        return DB_FILE_RECORDS[file_hash]

    # Check if file exists in database
    file_record = AnalysisFile.query.filter_by(sha256_hash=file_hash).first()

    if not file_record:
        # Create new file record
        file_size = os.path.getsize(file_path)
        filename = os.path.basename(file_path)
        file_type = identify_file_type(file_path)

        file_record = AnalysisFile(
            filename=filename,
            filepath=file_path,
            file_size=file_size,
            file_type=file_type,
            mime_type=file_type,
            sha256_hash=file_hash,
            status=FileStatus.PROCESSING,
            is_root_file=(file_path == IMAGE_PATH),
            created_by=ADMIN_USER_ID,
            created_at=datetime.utcnow()
        )
        db.session.add(file_record)
        db.session.commit()
        logger.info(f"Created new file record for {filename} with ID {file_record.id}")
    else:
        logger.info(f"Found existing file record for {os.path.basename(file_path)} with ID {file_record.id}")

    # Cache the file record
    DB_FILE_RECORDS[file_hash] = file_record

    return file_record

def main():
    """Main function to orchestrate the recursive extraction"""
    logger.info("Starting recursive steganography and file carving extraction")

    # Verify the image exists
    if not os.path.exists(IMAGE_PATH):
        logger.error(f"Image file not found at {IMAGE_PATH}")
        return

    # Create output directory
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # Create Flask app and application context
    app = create_app()
    with app.app_context():
        # Process the initial file
        process_file(IMAGE_PATH, OUTPUT_DIR, 0)

        logger.info("Extraction complete!")
        print_summary()

def process_file(file_path: str, output_dir: str, depth: int) -> None:
    """
    Process a file by extracting hidden data and recursively analyzing extracted files

    Args:
        file_path: Path to the file to process
        output_dir: Directory to save extracted files
        depth: Current recursion depth
    """
    if depth > MAX_DEPTH:
        logger.warning(f"Maximum recursion depth reached for {file_path}")
        return

    # Calculate file hash to avoid processing the same file twice
    file_hash = calculate_file_hash(file_path)
    if file_hash in PROCESSED_FILES:
        logger.info(f"File {file_path} already processed (hash: {file_hash})")
        return

    PROCESSED_FILES.add(file_hash)

    logger.info(f"Processing file: {file_path} (depth: {depth})")

    # Create subdirectory for this file
    file_basename = os.path.basename(file_path)
    file_output_dir = os.path.join(output_dir, f"{file_basename}_extracted")
    os.makedirs(file_output_dir, exist_ok=True)

    # Get or create file record in database
    file_record = get_or_create_file_record(file_path)

    # Identify file type
    file_type = identify_file_type(file_path)
    logger.info(f"File type: {file_type}")

    # Run appropriate extractors based on file type
    if "image/png" in file_type:
        extract_from_png(file_path, file_output_dir, depth, file_record)
    elif "image/jpeg" in file_type:
        extract_from_jpeg(file_path, file_output_dir, depth, file_record)
    elif "application/zip" in file_type or "archive" in file_type.lower():
        extract_from_archive(file_path, file_output_dir, depth, file_record)
    elif "text" in file_type.lower():
        extract_from_text(file_path, file_output_dir, depth, file_record)

    # Always run binwalk for thorough extraction
    extract_with_binwalk(file_path, file_output_dir, depth, file_record)

    # Always run strings analysis
    extract_strings(file_path, file_output_dir, depth, file_record)

    # Run file command on the file
    run_file_command(file_path, file_output_dir, file_record)

    # Try exotic extraction methods
    try_exotic_extractions(file_path, file_output_dir, depth, file_record)

    # Mark file as analyzed
    file_record.status = FileStatus.COMPLETE
    file_record.analyzed_at = datetime.utcnow()
    file_record.analyzed_by = ADMIN_USER_ID
    db.session.commit()

    # Process any files that were extracted
    process_extracted_files(file_output_dir, depth + 1)

def calculate_file_hash(file_path: str) -> str:
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def identify_file_type(file_path: str) -> str:
    """Identify file type using python-magic"""
    try:
        return magic.from_file(file_path, mime=True)
    except:
        # Fallback to file command
        try:
            result = subprocess.run(['file', '--mime-type', file_path], 
                                   capture_output=True, text=True, check=True)
            return result.stdout.split(': ')[1].strip()
        except:
            return "application/octet-stream"  # Default to binary

def extract_from_png(file_path: str, output_dir: str, depth: int, file_record: AnalysisFile = None) -> None:
    """Extract data from PNG files"""
    logger.info(f"Extracting data from PNG file: {file_path}")

    # Analyze PNG structure
    analysis_results = analyze_png_file(file_path)
    with open(os.path.join(output_dir, "png_analysis.json"), 'w') as f:
        f.write(str(analysis_results))

    # Store analysis results in database if file record is provided
    if file_record:
        content = FileContent(
            file_id=file_record.id,
            content_type="png_analysis",
            content_format="json",
            content_json=analysis_results,
            content_size=len(str(analysis_results)),
            extracted_at=datetime.utcnow(),
            extracted_by=ADMIN_USER_ID,
            extraction_method="png_analyzer"
        )
        db.session.add(content)

        # Create findings for suspicious chunks
        if 'suspicious_chunks' in analysis_results:
            for chunk in analysis_results['suspicious_chunks']:
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="suspicious_chunk",
                    category="steganography",
                    title=f"Suspicious PNG chunk: {chunk['type']}",
                    description=f"Found suspicious PNG chunk of type {chunk['type']} with length {chunk['length']} bytes. Reason: {chunk.get('reason', 'Non-standard chunk')}",
                    confidence_level=7,
                    priority=6,
                    severity="medium",
                    analysis_method="png_analyzer",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow()
                )
                db.session.add(finding)

    # Extract metadata
    metadata_results = extract_png_metadata(file_path)
    with open(os.path.join(output_dir, "png_metadata.json"), 'w') as f:
        f.write(str(metadata_results))

    # Store metadata results in database if file record is provided
    if file_record:
        content = FileContent(
            file_id=file_record.id,
            content_type="png_metadata",
            content_format="json",
            content_json=metadata_results,
            content_size=len(str(metadata_results)),
            extracted_at=datetime.utcnow(),
            extracted_by=ADMIN_USER_ID,
            extraction_method="png_analyzer"
        )
        db.session.add(content)

        # Create findings for text data
        if 'text_data' in metadata_results and metadata_results['text_data']:
            for text_item in metadata_results['text_data']:
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="metadata_text",
                    category="steganography",
                    title=f"Text data in PNG: {text_item['keyword']}",
                    description=f"Found text data with keyword '{text_item['keyword']}' and content: {text_item['text']}",
                    confidence_level=8,
                    priority=6,
                    severity="medium",
                    analysis_method="png_analyzer",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow()
                )
                db.session.add(finding)

        db.session.commit()

    # Extract text chunks
    if 'text_data' in metadata_results and metadata_results['text_data']:
        with open(os.path.join(output_dir, "png_text_chunks.txt"), 'w') as f:
            for text_item in metadata_results['text_data']:
                f.write(f"Keyword: {text_item.get('keyword', 'Unknown')}\n")
                f.write(f"Text: {text_item.get('text', 'Unknown')}\n")
                f.write(f"Type: {text_item.get('type', 'Unknown')}\n\n")

    # Run zsteg extractors with all options
    # Regular bitplane extractors
    zsteg_extractors = ['zsteg', 'zsteg_bitplane_1', 'zsteg_bitplane_2', 'zsteg_bitplane_3', 'zsteg_bitplane_4']

    # Column order based extractors
    column_orders = ['xy', 'yx', 'xY', 'Xy', 'YX', 'XY']

    # Process all bitplanes with different orders
    for extractor_name in zsteg_extractors:
        # Regular extraction
        extract_with_tool(file_path, output_dir, extractor_name, file_record)

        # Column order based extractions
        for order in column_orders:
            params = {'order': order}
            extract_with_tool(file_path, output_dir, extractor_name, file_record, params)

    # Try spiral extraction
    spiral_params = {'order': 'spiral'}
    for i in range(1, 9):  # All bitplanes 1-8
        bitplane_spiral_params = spiral_params.copy()
        bitplane_spiral_params['bitplane'] = i
        extract_with_tool(file_path, output_dir, 'zsteg', file_record, bitplane_spiral_params)

    # Run advanced extraction techniques
    logger.info("Running advanced extraction techniques")

    # XOR bitplanes extraction
    for bp1 in range(1, 5):
        for bp2 in range(bp1 + 1, 6):
            for channel in ['r', 'g', 'b']:
                xor_params = {
                    'bitplane1': bp1,
                    'bitplane2': bp2,
                    'channel': channel
                }
                extract_with_tool(file_path, output_dir, 'xor_bitplanes', file_record, xor_params)

    # Combined bitplanes extraction
    for combine_method in ['concat', 'interleave', 'or']:
        # Try different combinations of bitplanes
        bitplane_combinations = [
            [1, 2, 3],  # Lower bitplanes
            [6, 7, 8],  # Higher bitplanes
            [1, 4, 8],  # Spread bitplanes
            [1, 2, 3, 4]  # More bitplanes
        ]

        for bitplanes in bitplane_combinations:
            for channel in ['r', 'g', 'b']:
                combined_params = {
                    'bitplanes': bitplanes,
                    'channel': channel,
                    'combine_method': combine_method
                }
                extract_with_tool(file_path, output_dir, 'combined_bitplanes', file_record, combined_params)

    # DCT extraction
    for block_size in [8, 16]:
        for coefficient in ['lsb', 'msb', 'mid', 'ac']:
            dct_params = {
                'block_size': block_size,
                'coefficient': coefficient
            }
            extract_with_tool(file_path, output_dir, 'dct_extract', file_record, dct_params)

    # Run advanced extraction techniques
    logger.info("Running advanced extraction techniques")

    # XOR bitplanes extraction
    for bp1 in range(1, 5):
        for bp2 in range(bp1 + 1, 6):
            for channel in ['r', 'g', 'b']:
                xor_params = {
                    'bitplane1': bp1,
                    'bitplane2': bp2,
                    'channel': channel
                }
                extract_with_tool(file_path, output_dir, 'xor_bitplanes', file_record, xor_params)

    # Combined bitplanes extraction
    for combine_method in ['concat', 'interleave', 'or']:
        # Try different combinations of bitplanes
        bitplane_combinations = [
            [1, 2, 3],  # Lower bitplanes
            [6, 7, 8],  # Higher bitplanes
            [1, 4, 8],  # Spread bitplanes
            [1, 2, 3, 4]  # More bitplanes
        ]

        for bitplanes in bitplane_combinations:
            for channel in ['r', 'g', 'b']:
                combined_params = {
                    'bitplanes': bitplanes,
                    'channel': channel,
                    'combine_method': combine_method
                }
                extract_with_tool(file_path, output_dir, 'combined_bitplanes', file_record, combined_params)

    # DCT extraction
    for block_size in [8, 16]:
        for coefficient in ['lsb', 'msb', 'mid', 'ac']:
            dct_params = {
                'block_size': block_size,
                'coefficient': coefficient
            }
            extract_with_tool(file_path, output_dir, 'dct_extract', file_record, dct_params)

def extract_from_jpeg(file_path: str, output_dir: str, depth: int, file_record: AnalysisFile = None) -> None:
    """Extract data from JPEG files"""
    logger.info(f"Extracting data from JPEG file: {file_path}")

    # Run steghide
    extract_with_tool(file_path, output_dir, 'steghide', file_record)

    # Run DCT extraction (especially relevant for JPEG files)
    logger.info("Running DCT extraction on JPEG file")
    for block_size in [8, 16]:
        for coefficient in ['lsb', 'msb', 'mid', 'ac']:
            dct_params = {
                'block_size': block_size,
                'coefficient': coefficient
            }
            extract_with_tool(file_path, output_dir, 'dct_extract', file_record, dct_params)

    # Run XOR bitplanes extraction
    logger.info("Running XOR bitplanes extraction on JPEG file")
    for bp1 in range(1, 5):
        for bp2 in range(bp1 + 1, 6):
            for channel in ['r', 'g', 'b']:
                xor_params = {
                    'bitplane1': bp1,
                    'bitplane2': bp2,
                    'channel': channel
                }
                extract_with_tool(file_path, output_dir, 'xor_bitplanes', file_record, xor_params)

    # Run combined bitplanes extraction
    logger.info("Running combined bitplanes extraction on JPEG file")
    for combine_method in ['concat', 'interleave', 'or']:
        # Try different combinations of bitplanes
        bitplane_combinations = [
            [1, 2, 3],  # Lower bitplanes
            [6, 7, 8],  # Higher bitplanes
            [1, 4, 8],  # Spread bitplanes
            [1, 2, 3, 4]  # More bitplanes
        ]

        for bitplanes in bitplane_combinations:
            for channel in ['r', 'g', 'b']:
                combined_params = {
                    'bitplanes': bitplanes,
                    'channel': channel,
                    'combine_method': combine_method
                }
                extract_with_tool(file_path, output_dir, 'combined_bitplanes', file_record, combined_params)

    # Run outguess if available
    try:
        outguess_output = os.path.join(output_dir, "outguess_extracted")
        subprocess.run(['outguess', '-r', file_path, outguess_output], check=True)
        logger.info(f"Outguess extraction successful: {outguess_output}")

        # Store outguess results in database if file record is provided
        if file_record and os.path.exists(outguess_output):
            with open(outguess_output, 'rb') as f:
                outguess_data = f.read()

            # Store outguess data as file content
            content = FileContent(
                file_id=file_record.id,
                content_type="outguess_extracted_data",
                content_format="binary",
                content_bytes=outguess_data,
                content_size=len(outguess_data),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="outguess"
            )
            db.session.add(content)

            # Create finding
            finding = Finding(
                file_id=file_record.id,
                finding_type="steganography",
                category="steganography",
                title="Hidden data found with outguess",
                description=f"Found hidden data using outguess. Extracted {len(outguess_data)} bytes.",
                confidence_level=8,
                priority=7,
                severity="high",
                analysis_method="outguess",
                created_by=ADMIN_USER_ID,
                created_at=datetime.utcnow()
            )
            db.session.add(finding)
            db.session.commit()
    except:
        logger.warning("Outguess extraction failed or not available")

def extract_from_archive(file_path: str, output_dir: str, depth: int, file_record: AnalysisFile = None) -> None:
    """Extract data from archive files"""
    logger.info(f"Extracting data from archive file: {file_path}")

    # Create directory for extracted archive contents
    archive_output_dir = os.path.join(output_dir, "archive_contents")
    os.makedirs(archive_output_dir, exist_ok=True)

    # Try different extraction methods based on file type
    file_type = identify_file_type(file_path)

    try:
        extraction_method = ""
        extraction_command = ""
        extracted_files = []

        if "zip" in file_type.lower():
            # Try unzip
            extraction_method = "unzip"
            extraction_command = f"unzip -o -d {archive_output_dir} {file_path}"
            result = subprocess.run(['unzip', '-o', '-d', archive_output_dir, file_path], 
                          stderr=subprocess.PIPE, stdout=subprocess.PIPE)

            # Get list of extracted files
            for line in result.stdout.decode('utf-8', errors='ignore').splitlines():
                if line.startswith('  inflating: ') or line.startswith('   creating: '):
                    extracted_file = line.split(': ', 1)[1].strip()
                    extracted_files.append(os.path.join(archive_output_dir, extracted_file))

        elif "gzip" in file_type.lower():
            # Try gunzip (need to copy file first as gunzip removes original)
            extraction_method = "gunzip"
            temp_file = os.path.join(output_dir, "temp_gzip")
            shutil.copy2(file_path, temp_file)
            extraction_command = f"gunzip -f {temp_file}"
            subprocess.run(['gunzip', '-f', temp_file], stderr=subprocess.PIPE)

            # Get extracted file
            extracted_file = temp_file[:-3] if temp_file.endswith('.gz') else temp_file
            if os.path.exists(extracted_file):
                extracted_files.append(extracted_file)

        elif "bzip2" in file_type.lower():
            # Try bunzip2 (need to copy file first as bunzip2 removes original)
            extraction_method = "bunzip2"
            temp_file = os.path.join(output_dir, "temp_bzip2")
            shutil.copy2(file_path, temp_file)
            extraction_command = f"bunzip2 -f {temp_file}"
            subprocess.run(['bunzip2', '-f', temp_file], stderr=subprocess.PIPE)

            # Get extracted file
            extracted_file = temp_file[:-4] if temp_file.endswith('.bz2') else temp_file
            if os.path.exists(extracted_file):
                extracted_files.append(extracted_file)

        elif "tar" in file_type.lower():
            # Try tar
            extraction_method = "tar"
            extraction_command = f"tar -xf {file_path} -C {archive_output_dir}"
            result = subprocess.run(['tar', '-xf', file_path, '-C', archive_output_dir], 
                          stderr=subprocess.PIPE, stdout=subprocess.PIPE)

            # Get list of extracted files
            for root, dirs, files in os.walk(archive_output_dir):
                for file in files:
                    extracted_files.append(os.path.join(root, file))

        elif "rar" in file_type.lower():
            # Try unrar
            extraction_method = "unrar"
            extraction_command = f"unrar x {file_path} {archive_output_dir}"
            result = subprocess.run(['unrar', 'x', file_path, archive_output_dir], 
                          stderr=subprocess.PIPE, stdout=subprocess.PIPE)

            # Get list of extracted files
            for root, dirs, files in os.walk(archive_output_dir):
                for file in files:
                    extracted_files.append(os.path.join(root, file))

        elif "7z" in file_type.lower():
            # Try 7z
            extraction_method = "7z"
            extraction_command = f"7z x -o{archive_output_dir} {file_path}"
            result = subprocess.run(['7z', 'x', '-o' + archive_output_dir, file_path], 
                          stderr=subprocess.PIPE, stdout=subprocess.PIPE)

            # Get list of extracted files
            for root, dirs, files in os.walk(archive_output_dir):
                for file in files:
                    extracted_files.append(os.path.join(root, file))

        else:
            # Try binwalk as a fallback
            logger.info(f"Unknown archive type, using binwalk for extraction")
            extract_with_binwalk(file_path, archive_output_dir, depth, file_record)
            return

        # Store extraction results in database if file record is provided
        if file_record and extracted_files:
            # Store extraction info as file content
            content = FileContent(
                file_id=file_record.id,
                content_type=f"{extraction_method}_extraction_results",
                content_format="json",
                content_json={
                    'extraction_method': extraction_method,
                    'extraction_command': extraction_command,
                    'extracted_files': [os.path.basename(f) for f in extracted_files],
                    'extracted_count': len(extracted_files)
                },
                content_size=len(str(extracted_files)),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method=extraction_method
            )
            db.session.add(content)

            # Create finding
            finding = Finding(
                file_id=file_record.id,
                finding_type="archive_extraction",
                category="file_carving",
                title=f"Archive contents extracted with {extraction_method}",
                description=f"Extracted {len(extracted_files)} files from archive using {extraction_method}.",
                confidence_level=9,
                priority=7,
                severity="medium",
                analysis_method=extraction_method,
                created_by=ADMIN_USER_ID,
                created_at=datetime.utcnow()
            )
            db.session.add(finding)

            # Create file records for extracted files
            for extracted_file in extracted_files:
                if os.path.exists(extracted_file) and os.path.getsize(extracted_file) > 0:
                    # Create a new file record for the extracted file
                    extracted_file_hash = calculate_file_hash(extracted_file)
                    extracted_file_record = AnalysisFile.query.filter_by(sha256_hash=extracted_file_hash).first()

                    if not extracted_file_record:
                        extracted_file_type = identify_file_type(extracted_file)
                        extracted_file_record = AnalysisFile(
                            filename=os.path.basename(extracted_file),
                            filepath=extracted_file,
                            file_size=os.path.getsize(extracted_file),
                            file_type=extracted_file_type,
                            mime_type=extracted_file_type,
                            sha256_hash=extracted_file_hash,
                            status=FileStatus.PROCESSING,
                            is_root_file=False,
                            parent_file_sha=file_record.sha256_hash,
                            created_by=ADMIN_USER_ID,
                            created_at=datetime.utcnow()
                        )
                        db.session.add(extracted_file_record)
                        db.session.flush()  # Get the ID

                    # Create relationship
                    relationship = ExtractionRelationship(
                        source_file_id=file_record.id,
                        source_file_sha=file_record.sha256_hash,
                        extracted_file_id=extracted_file_record.id,
                        extracted_file_sha=extracted_file_record.sha256_hash,
                        extraction_method=extraction_method,
                        extraction_tool_version="1.0",
                        extraction_command=extraction_command,
                        confidence_score=0.9,
                        extra_data={}
                    )
                    db.session.add(relationship)

                    # Cache the extracted file record
                    DB_FILE_RECORDS[extracted_file_hash] = extracted_file_record

            db.session.commit()

    except Exception as e:
        logger.error(f"Error extracting archive: {str(e)}")

def extract_from_text(file_path: str, output_dir: str, depth: int, file_record: AnalysisFile = None) -> None:
    """Extract data from text files"""
    logger.info(f"Extracting data from text file: {file_path}")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Copy the text file to the output directory
    text_output = os.path.join(output_dir, "text_content.txt")
    shutil.copy2(file_path, text_output)

    # Store text content in database if file record is provided
    if file_record:
        try:
            with open(file_path, 'r', errors='ignore') as f:
                text_content = f.read()

            # Store text content as file content
            content = FileContent(
                file_id=file_record.id,
                content_type="text_content",
                content_format="text",
                content_text=text_content,
                content_size=len(text_content),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="text_extraction"
            )
            db.session.add(content)
            db.session.commit()
        except Exception as e:
            logger.error(f"Error storing text content in database: {str(e)}")

    # Look for base64 encoded data
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()

        # Look for base64 patterns
        import re
        import base64

        # Find potential base64 strings (at least 20 chars long)
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, content)

        if matches:
            logger.info(f"Found {len(matches)} potential base64 strings")
            base64_dir = os.path.join(output_dir, "base64_decoded")
            os.makedirs(base64_dir, exist_ok=True)

            # Store base64 findings in database if file record is provided
            if file_record:
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="encoded_data",
                    category="steganography",
                    title=f"Base64 encoded data found",
                    description=f"Found {len(matches)} potential base64 encoded strings in text file.",
                    confidence_level=7,
                    priority=6,
                    severity="medium",
                    analysis_method="text_analysis",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data={'base64_count': len(matches)}
                )
                db.session.add(finding)
                db.session.commit()

            for i, match in enumerate(matches):
                try:
                    # Try to decode as base64
                    decoded = base64.b64decode(match)
                    output_file = os.path.join(base64_dir, f"decoded_{i}")
                    with open(output_file, 'wb') as f:
                        f.write(decoded)
                    logger.info(f"Decoded base64 string to {output_file} ({len(decoded)} bytes)")

                    # Store decoded data in database if file record is provided
                    if file_record:
                        # Create a new file record for the decoded data
                        decoded_file_hash = hashlib.sha256(decoded).hexdigest()
                        decoded_file_record = AnalysisFile.query.filter_by(sha256_hash=decoded_file_hash).first()

                        if not decoded_file_record:
                            # Save decoded data to file
                            temp_dir = os.path.join('bulk_uploads/discovered_files')
                            os.makedirs(temp_dir, exist_ok=True)
                            temp_file = os.path.join(temp_dir, f"{os.path.basename(file_path)}_base64_decoded_{i}")
                            with open(temp_file, 'wb') as f:
                                f.write(decoded)

                            # Try to identify file type
                            decoded_file_type = identify_file_type(output_file)

                            decoded_file_record = AnalysisFile(
                                filename=f"{os.path.basename(file_path)}_base64_decoded_{i}",
                                filepath=temp_file,
                                file_size=len(decoded),
                                file_type=decoded_file_type,
                                mime_type=decoded_file_type,
                                sha256_hash=decoded_file_hash,
                                status=FileStatus.PROCESSING,
                                is_root_file=False,
                                parent_file_sha=file_record.sha256_hash,
                                created_by=ADMIN_USER_ID,
                                created_at=datetime.utcnow()
                            )
                            db.session.add(decoded_file_record)
                            db.session.flush()  # Get the ID

                        # Create relationship
                        relationship = ExtractionRelationship(
                            source_file_id=file_record.id,
                            source_file_sha=file_record.sha256_hash,
                            extracted_file_id=decoded_file_record.id,
                            extracted_file_sha=decoded_file_record.sha256_hash,
                            extraction_method="base64_decode",
                            extraction_tool_version="1.0",
                            extraction_command="base64 -d",
                            confidence_score=0.8,
                            extra_data={'original_string': match[:100] + '...' if len(match) > 100 else match}
                        )
                        db.session.add(relationship)

                        # Cache the decoded file record
                        DB_FILE_RECORDS[decoded_file_hash] = decoded_file_record
                        db.session.commit()
                except:
                    pass  # Not valid base64
    except Exception as e:
        logger.error(f"Error processing text file: {str(e)}")

    # Look for hex encoded data
    try:
        with open(file_path, 'r', errors='ignore') as f:
            content = f.read()

        # Look for hex patterns (pairs of hex digits)
        import re

        # Find potential hex strings (at least 20 bytes / 40 hex chars)
        hex_pattern = r'[0-9a-fA-F]{40,}'
        matches = re.findall(hex_pattern, content)

        if matches:
            logger.info(f"Found {len(matches)} potential hex strings")
            hex_dir = os.path.join(output_dir, "hex_decoded")
            os.makedirs(hex_dir, exist_ok=True)

            # Store hex findings in database if file record is provided
            if file_record:
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="encoded_data",
                    category="steganography",
                    title=f"Hex encoded data found",
                    description=f"Found {len(matches)} potential hex encoded strings in text file.",
                    confidence_level=7,
                    priority=6,
                    severity="medium",
                    analysis_method="text_analysis",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data={'hex_count': len(matches)}
                )
                db.session.add(finding)
                db.session.commit()

            for i, match in enumerate(matches):
                try:
                    # Try to decode as hex
                    if len(match) % 2 == 0:  # Valid hex string must have even length
                        decoded = bytes.fromhex(match)
                        output_file = os.path.join(hex_dir, f"decoded_{i}")
                        with open(output_file, 'wb') as f:
                            f.write(decoded)
                        logger.info(f"Decoded hex string to {output_file} ({len(decoded)} bytes)")

                        # Store decoded data in database if file record is provided
                        if file_record:
                            # Create a new file record for the decoded data
                            decoded_file_hash = hashlib.sha256(decoded).hexdigest()
                            decoded_file_record = AnalysisFile.query.filter_by(sha256_hash=decoded_file_hash).first()

                            if not decoded_file_record:
                                # Save decoded data to file
                                temp_dir = os.path.join('bulk_uploads/discovered_files')
                                os.makedirs(temp_dir, exist_ok=True)
                                temp_file = os.path.join(temp_dir, f"{os.path.basename(file_path)}_hex_decoded_{i}")
                                with open(temp_file, 'wb') as f:
                                    f.write(decoded)

                                # Try to identify file type
                                decoded_file_type = identify_file_type(output_file)

                                decoded_file_record = AnalysisFile(
                                    filename=f"{os.path.basename(file_path)}_hex_decoded_{i}",
                                    filepath=temp_file,
                                    file_size=len(decoded),
                                    file_type=decoded_file_type,
                                    mime_type=decoded_file_type,
                                    sha256_hash=decoded_file_hash,
                                    status=FileStatus.PROCESSING,
                                    is_root_file=False,
                                    parent_file_sha=file_record.sha256_hash,
                                    created_by=ADMIN_USER_ID,
                                    created_at=datetime.utcnow()
                                )
                                db.session.add(decoded_file_record)
                                db.session.flush()  # Get the ID

                            # Create relationship
                            relationship = ExtractionRelationship(
                                source_file_id=file_record.id,
                                source_file_sha=file_record.sha256_hash,
                                extracted_file_id=decoded_file_record.id,
                                extracted_file_sha=decoded_file_record.sha256_hash,
                                extraction_method="hex_decode",
                                extraction_tool_version="1.0",
                                extraction_command="xxd -r -p",
                                confidence_score=0.8,
                                extra_data={'original_string': match[:100] + '...' if len(match) > 100 else match}
                            )
                            db.session.add(relationship)

                            # Cache the decoded file record
                            DB_FILE_RECORDS[decoded_file_hash] = decoded_file_record
                            db.session.commit()
                except:
                    pass  # Not valid hex
    except Exception as e:
        logger.error(f"Error processing text file for hex: {str(e)}")

def extract_with_binwalk(file_path: str, output_dir: str, depth: int, file_record: AnalysisFile = None) -> None:
    """Extract data using binwalk"""
    logger.info(f"Extracting data with binwalk: {file_path}")

    # Create directory for binwalk extraction
    binwalk_dir = os.path.join(output_dir, "binwalk_extracted")
    os.makedirs(binwalk_dir, exist_ok=True)

    try:
        # Run binwalk with extraction
        extraction_process = subprocess.run(['binwalk', '-e', '--dd=.*', '-C', binwalk_dir, file_path], 
                      stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # Also run binwalk to get signature analysis
        result = subprocess.run(['binwalk', file_path], capture_output=True, text=True)
        with open(os.path.join(output_dir, "binwalk_analysis.txt"), 'w') as f:
            f.write(result.stdout)

        # Store binwalk results in database if file record is provided
        if file_record:
            # Store binwalk analysis as file content
            content = FileContent(
                file_id=file_record.id,
                content_type="binwalk_analysis",
                content_format="text",
                content_text=result.stdout,
                content_size=len(result.stdout),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="binwalk"
            )
            db.session.add(content)

            # Parse binwalk output to find signatures
            signatures = []
            for line in result.stdout.split('\n'):
                if line and not line.startswith('DECIMAL') and not line.startswith('-'):
                    parts = line.strip().split(None, 2)
                    if len(parts) >= 3:
                        try:
                            offset = int(parts[0])
                            description = parts[2]
                            signatures.append({
                                'offset': offset,
                                'description': description
                            })
                        except:
                            pass

            # Create finding for binwalk signatures
            if signatures:
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="file_carving",
                    category="file_carving",
                    title=f"Binwalk signatures found",
                    description=f"Found {len(signatures)} file signatures using binwalk.",
                    confidence_level=8,
                    priority=7,
                    severity="medium",
                    analysis_method="binwalk",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data={'signatures': signatures}
                )
                db.session.add(finding)

            # Find extracted files
            extracted_files = []
            for root, dirs, files in os.walk(binwalk_dir):
                for file in files:
                    file_path_full = os.path.join(root, file)
                    if os.path.isfile(file_path_full) and os.path.getsize(file_path_full) > 0:
                        extracted_files.append(file_path_full)

            # Create finding for extracted files
            if extracted_files:
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="file_carving",
                    category="file_carving",
                    title=f"Binwalk extracted files",
                    description=f"Extracted {len(extracted_files)} files using binwalk.",
                    confidence_level=9,
                    priority=8,
                    severity="high",
                    analysis_method="binwalk",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data={'extracted_count': len(extracted_files)}
                )
                db.session.add(finding)

                # Create file records for extracted files
                for extracted_file in extracted_files:
                    if os.path.exists(extracted_file) and os.path.getsize(extracted_file) > 0:
                        # Calculate hash
                        extracted_file_hash = calculate_file_hash(extracted_file)

                        # Check if file already exists in database
                        extracted_file_record = AnalysisFile.query.filter_by(sha256_hash=extracted_file_hash).first()

                        if not extracted_file_record:
                            # Identify file type
                            extracted_file_type = identify_file_type(extracted_file)

                            # Create new file record
                            extracted_file_record = AnalysisFile(
                                filename=os.path.basename(extracted_file),
                                filepath=extracted_file,
                                file_size=os.path.getsize(extracted_file),
                                file_type=extracted_file_type,
                                mime_type=extracted_file_type,
                                sha256_hash=extracted_file_hash,
                                status=FileStatus.PROCESSING,
                                is_root_file=False,
                                parent_file_sha=file_record.sha256_hash,
                                created_by=ADMIN_USER_ID,
                                created_at=datetime.utcnow()
                            )
                            db.session.add(extracted_file_record)
                            db.session.flush()  # Get the ID

                        # Create relationship
                        relationship = ExtractionRelationship(
                            source_file_id=file_record.id,
                            source_file_sha=file_record.sha256_hash,
                            extracted_file_id=extracted_file_record.id,
                            extracted_file_sha=extracted_file_record.sha256_hash,
                            extraction_method="binwalk",
                            extraction_tool_version="1.0",
                            extraction_command="binwalk -e --dd=.* -C " + binwalk_dir,
                            confidence_score=0.9,
                            extra_data={}
                        )
                        db.session.add(relationship)

                        # Cache the extracted file record
                        DB_FILE_RECORDS[extracted_file_hash] = extracted_file_record

            db.session.commit()

        logger.info(f"Binwalk extraction complete: {binwalk_dir}")
    except Exception as e:
        logger.error(f"Error running binwalk: {str(e)}")

def extract_strings(file_path: str, output_dir: str, depth: int, file_record: AnalysisFile = None) -> None:
    """Extract strings from file"""
    logger.info(f"Extracting strings from file: {file_path}")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Run strings command
        result = subprocess.run(['strings', file_path], capture_output=True, text=True)
        with open(os.path.join(output_dir, "strings_output.txt"), 'w') as f:
            f.write(result.stdout)

        # Store strings results in database if file record is provided
        if file_record:
            # Store strings output as file content
            content = FileContent(
                file_id=file_record.id,
                content_type="strings_output",
                content_format="text",
                content_text=result.stdout,
                content_size=len(result.stdout),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="strings"
            )
            db.session.add(content)

            # Analyze strings for interesting patterns
            strings_analysis = analyze_strings(result.stdout)

            # Store strings analysis as file content
            analysis_content = FileContent(
                file_id=file_record.id,
                content_type="strings_analysis",
                content_format="json",
                content_json=strings_analysis,
                content_size=len(str(strings_analysis)),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="strings_analysis"
            )
            db.session.add(analysis_content)

            # Create findings for interesting patterns
            if strings_analysis['interesting_strings']:
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="interesting_strings",
                    category="string_analysis",
                    title=f"Interesting strings found",
                    description=f"Found {len(strings_analysis['interesting_strings'])} interesting strings.",
                    confidence_level=7,
                    priority=6,
                    severity="medium",
                    analysis_method="strings",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data={'interesting_count': len(strings_analysis['interesting_strings'])}
                )
                db.session.add(finding)

            # Create findings for specific pattern types
            for pattern_type, patterns in strings_analysis['patterns'].items():
                if patterns:
                    finding = Finding(
                        file_id=file_record.id,
                        finding_type=f"string_pattern_{pattern_type}",
                        category="string_analysis",
                        title=f"{pattern_type.replace('_', ' ').title()} found",
                        description=f"Found {len(patterns)} {pattern_type.replace('_', ' ')} patterns.",
                        confidence_level=8,
                        priority=7,
                        severity="medium",
                        analysis_method="strings",
                        created_by=ADMIN_USER_ID,
                        created_at=datetime.utcnow(),
                        evidence_data={pattern_type: patterns[:10]}  # Store first 10 patterns
                    )
                    db.session.add(finding)

            db.session.commit()

        logger.info(f"Strings extraction complete")
    except Exception as e:
        logger.error(f"Error running strings: {str(e)}")

def analyze_strings(strings_output: str) -> Dict[str, Any]:
    """Analyze strings output for interesting patterns"""
    lines = strings_output.split('\n')

    analysis = {
        'total_strings': len(lines),
        'interesting_strings': [],
        'patterns': {
            'emails': [],
            'urls': [],
            'ips': [],
            'base64_candidates': [],
            'hex_strings': [],
            'flags': [],
            'passwords': [],
            'crypto_addresses': [],
            'file_paths': []
        }
    }

    # Keywords that make strings interesting
    interesting_keywords = [
        'flag', 'password', 'secret', 'key', 'token', 'auth', 'login',
        'admin', 'root', 'config', 'database', 'crypto', 'bitcoin',
        'wallet', 'private', 'public', 'certificate', 'ssh', 'rsa',
        'bodhi', 'tree', 'blossom'  # Special keywords from the task
    ]

    # Pattern definitions
    patterns = {
        'emails': r'[\w\.-]+@[\w\.-]+\.\w+',
        'urls': r'https?://[\w\.-]+(?:/\S*)?',
        'ips': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'base64_candidates': r'^[A-Za-z0-9+/]{20,}={0,2}$',
        'hex_strings': r'^[0-9a-fA-F]{32,}$',
        'flags': r'flag\{[^}]+\}|CTF\{[^}]+\}|FLAG\{[^}]+\}',
        'passwords': r'(?:password|passwd|pwd)[\s:=]+\S+',
        'crypto_addresses': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\b0x[a-fA-F0-9]{40}\b',
        'file_paths': r'(?:[a-zA-Z]:\\|/)(?:[^\\/:*?"<>|\r\n]+[\\\/])*[^\\/:*?"<>|\r\n]*'
    }

    for line in lines:
        line = line.strip()
        if len(line) < 4:
            continue

        # Check for interesting keywords
        line_lower = line.lower()
        if any(keyword in line_lower for keyword in interesting_keywords):
            analysis['interesting_strings'].append({
                'string': line,
                'type': 'keyword_match',
                'keywords': [kw for kw in interesting_keywords if kw in line_lower]
            })

        # Check against patterns
        for pattern_name, pattern in patterns.items():
            import re
            matches = re.findall(pattern, line, re.IGNORECASE)
            if matches:
                analysis['patterns'][pattern_name].extend(matches)
                if line not in [item.get('string', '') for item in analysis['interesting_strings']]:
                    analysis['interesting_strings'].append({
                        'string': line,
                        'type': pattern_name,
                        'matches': matches
                    })

    return analysis

def run_file_command(file_path: str, output_dir: str, file_record: AnalysisFile = None) -> None:
    """Run file command for detailed file analysis"""
    logger.info(f"Running file command on: {file_path}")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Run file command with different options
        result1 = subprocess.run(['file', file_path], capture_output=True, text=True)
        result2 = subprocess.run(['file', '-i', file_path], capture_output=True, text=True)
        result3 = subprocess.run(['file', '-k', file_path], capture_output=True, text=True)

        with open(os.path.join(output_dir, "file_analysis.txt"), 'w') as f:
            f.write(f"Standard file output:\n{result1.stdout}\n\n")
            f.write(f"MIME type:\n{result2.stdout}\n\n")
            f.write(f"Keep going (multiple file types):\n{result3.stdout}\n\n")

        # Store file command results in database if file record is provided
        if file_record:
            # Store file analysis as file content
            content = FileContent(
                file_id=file_record.id,
                content_type="file_analysis",
                content_format="text",
                content_text=f"Standard file output:\n{result1.stdout}\n\nMIME type:\n{result2.stdout}\n\nKeep going (multiple file types):\n{result3.stdout}\n\n",
                content_size=len(result1.stdout) + len(result2.stdout) + len(result3.stdout) + 100,
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="file_command"
            )
            db.session.add(content)

            # Parse MIME type
            mime_type = ""
            if result2.stdout:
                try:
                    mime_type = result2.stdout.split(': ')[1].strip()
                    if ';' in mime_type:
                        mime_type = mime_type.split(';')[0].strip()
                except:
                    pass

            # Update file record with correct file type if needed
            if mime_type and file_record.mime_type != mime_type:
                file_record.mime_type = mime_type
                file_record.file_type = mime_type

            # Check for interesting file types
            interesting_types = [
                'executable', 'compressed', 'archive', 'encrypted', 
                'certificate', 'private key', 'public key', 'image', 'audio', 'video'
            ]

            for interesting_type in interesting_types:
                if interesting_type.lower() in result1.stdout.lower():
                    finding = Finding(
                        file_id=file_record.id,
                        finding_type="file_type",
                        category="file_analysis",
                        title=f"Interesting file type: {interesting_type}",
                        description=f"File identified as {interesting_type} type: {result1.stdout}",
                        confidence_level=9,
                        priority=6,
                        severity="medium",
                        analysis_method="file_command",
                        created_by=ADMIN_USER_ID,
                        created_at=datetime.utcnow()
                    )
                    db.session.add(finding)

                    # Set special flags based on file type
                    if interesting_type.lower() == 'executable':
                        file_record.is_executable = True
                    elif interesting_type.lower() in ['compressed', 'archive']:
                        file_record.is_archive = True
                    elif interesting_type.lower() == 'encrypted':
                        file_record.is_encrypted = True

            db.session.commit()

        logger.info(f"File command analysis complete")
    except Exception as e:
        logger.error(f"Error running file command: {str(e)}")

def try_exotic_extractions(file_path: str, output_dir: str, depth: int, file_record: AnalysisFile = None) -> None:
    """Try exotic extraction methods"""
    logger.info(f"Trying exotic extraction methods on: {file_path}")

    # Create directory for exotic extractions
    exotic_dir = os.path.join(output_dir, "exotic_extractions")
    os.makedirs(exotic_dir, exist_ok=True)

    # Try foremost
    try:
        foremost_dir = os.path.join(exotic_dir, "foremost")
        os.makedirs(foremost_dir, exist_ok=True)
        foremost_result = subprocess.run(['foremost', '-o', foremost_dir, '-i', file_path], 
                      stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        logger.info(f"Foremost extraction complete: {foremost_dir}")

        # Store foremost results in database if file record is provided
        if file_record:
            # Check for audit.txt file which contains foremost results
            audit_file = os.path.join(foremost_dir, "audit.txt")
            if os.path.exists(audit_file):
                with open(audit_file, 'r') as f:
                    audit_content = f.read()

                # Store audit content as file content
                content = FileContent(
                    file_id=file_record.id,
                    content_type="foremost_audit",
                    content_format="text",
                    content_text=audit_content,
                    content_size=len(audit_content),
                    extracted_at=datetime.utcnow(),
                    extracted_by=ADMIN_USER_ID,
                    extraction_method="foremost"
                )
                db.session.add(content)

                # Create finding for foremost extraction
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="file_carving",
                    category="file_carving",
                    title="Foremost file carving results",
                    description=f"Foremost extracted files from the source file.",
                    confidence_level=8,
                    priority=7,
                    severity="medium",
                    analysis_method="foremost",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data={'audit_content': audit_content[:1000]}  # First 1000 chars
                )
                db.session.add(finding)

                # Find extracted files
                extracted_files = []
                for root, dirs, files in os.walk(foremost_dir):
                    for file in files:
                        if file != "audit.txt":  # Skip the audit file
                            file_path_full = os.path.join(root, file)
                            if os.path.isfile(file_path_full) and os.path.getsize(file_path_full) > 0:
                                extracted_files.append(file_path_full)

                # Create file records for extracted files
                for extracted_file in extracted_files:
                    if os.path.exists(extracted_file) and os.path.getsize(extracted_file) > 0:
                        # Calculate hash
                        extracted_file_hash = calculate_file_hash(extracted_file)

                        # Check if file already exists in database
                        extracted_file_record = AnalysisFile.query.filter_by(sha256_hash=extracted_file_hash).first()

                        if not extracted_file_record:
                            # Identify file type
                            extracted_file_type = identify_file_type(extracted_file)

                            # Create new file record
                            extracted_file_record = AnalysisFile(
                                filename=os.path.basename(extracted_file),
                                filepath=extracted_file,
                                file_size=os.path.getsize(extracted_file),
                                file_type=extracted_file_type,
                                mime_type=extracted_file_type,
                                sha256_hash=extracted_file_hash,
                                status=FileStatus.PROCESSING,
                                is_root_file=False,
                                parent_file_sha=file_record.sha256_hash,
                                created_by=ADMIN_USER_ID,
                                created_at=datetime.utcnow()
                            )
                            db.session.add(extracted_file_record)
                            db.session.flush()  # Get the ID

                        # Create relationship
                        relationship = ExtractionRelationship(
                            source_file_id=file_record.id,
                            source_file_sha=file_record.sha256_hash,
                            extracted_file_id=extracted_file_record.id,
                            extracted_file_sha=extracted_file_record.sha256_hash,
                            extraction_method="foremost",
                            extraction_tool_version="1.0",
                            extraction_command="foremost -o " + foremost_dir + " -i " + file_path,
                            confidence_score=0.9,
                            extra_data={}
                        )
                        db.session.add(relationship)

                        # Cache the extracted file record
                        DB_FILE_RECORDS[extracted_file_hash] = extracted_file_record

                db.session.commit()
    except Exception as e:
        logger.warning(f"Foremost extraction failed or not available: {str(e)}")

    # Try scalpel
    try:
        scalpel_dir = os.path.join(exotic_dir, "scalpel")
        os.makedirs(scalpel_dir, exist_ok=True)
        scalpel_result = subprocess.run(['scalpel', '-o', scalpel_dir, file_path], 
                      stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        logger.info(f"Scalpel extraction complete: {scalpel_dir}")

        # Store scalpel results in database if file record is provided
        if file_record:
            # Store scalpel output as file content
            content = FileContent(
                file_id=file_record.id,
                content_type="scalpel_output",
                content_format="text",
                content_text=scalpel_result.stdout.decode('utf-8', errors='ignore'),
                content_size=len(scalpel_result.stdout),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="scalpel"
            )
            db.session.add(content)

            # Find extracted files
            extracted_files = []
            for root, dirs, files in os.walk(scalpel_dir):
                for file in files:
                    file_path_full = os.path.join(root, file)
                    if os.path.isfile(file_path_full) and os.path.getsize(file_path_full) > 0:
                        extracted_files.append(file_path_full)

            # Create finding for scalpel extraction
            if extracted_files:
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="file_carving",
                    category="file_carving",
                    title="Scalpel file carving results",
                    description=f"Scalpel extracted {len(extracted_files)} files from the source file.",
                    confidence_level=8,
                    priority=7,
                    severity="medium",
                    analysis_method="scalpel",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data={'extracted_count': len(extracted_files)}
                )
                db.session.add(finding)

                # Create file records for extracted files
                for extracted_file in extracted_files:
                    # Calculate hash
                    extracted_file_hash = calculate_file_hash(extracted_file)

                    # Check if file already exists in database
                    extracted_file_record = AnalysisFile.query.filter_by(sha256_hash=extracted_file_hash).first()

                    if not extracted_file_record:
                        # Identify file type
                        extracted_file_type = identify_file_type(extracted_file)

                        # Create new file record
                        extracted_file_record = AnalysisFile(
                            filename=os.path.basename(extracted_file),
                            filepath=extracted_file,
                            file_size=os.path.getsize(extracted_file),
                            file_type=extracted_file_type,
                            mime_type=extracted_file_type,
                            sha256_hash=extracted_file_hash,
                            status=FileStatus.PROCESSING,
                            is_root_file=False,
                            parent_file_sha=file_record.sha256_hash,
                            created_by=ADMIN_USER_ID,
                            created_at=datetime.utcnow()
                        )
                        db.session.add(extracted_file_record)
                        db.session.flush()  # Get the ID

                    # Create relationship
                    relationship = ExtractionRelationship(
                        source_file_id=file_record.id,
                        source_file_sha=file_record.sha256_hash,
                        extracted_file_id=extracted_file_record.id,
                        extracted_file_sha=extracted_file_record.sha256_hash,
                        extraction_method="scalpel",
                        extraction_tool_version="1.0",
                        extraction_command="scalpel -o " + scalpel_dir + " " + file_path,
                        confidence_score=0.9,
                        extra_data={}
                    )
                    db.session.add(relationship)

                    # Cache the extracted file record
                    DB_FILE_RECORDS[extracted_file_hash] = extracted_file_record

            db.session.commit()
    except Exception as e:
        logger.warning(f"Scalpel extraction failed or not available: {str(e)}")

    # Try photorec
    try:
        photorec_dir = os.path.join(exotic_dir, "photorec")
        os.makedirs(photorec_dir, exist_ok=True)
        # PhotoRec is interactive, so we can't easily run it here
        logger.warning("PhotoRec is interactive and not automated in this script")
    except:
        pass

    # Try exiftool
    try:
        exiftool_result = subprocess.run(['exiftool', file_path], capture_output=True, text=True)
        with open(os.path.join(exotic_dir, "exiftool_output.txt"), 'w') as f:
            f.write(exiftool_result.stdout)
        logger.info(f"ExifTool extraction complete")

        # Store exiftool results in database if file record is provided
        if file_record:
            # Store exiftool output as file content
            content = FileContent(
                file_id=file_record.id,
                content_type="exiftool_output",
                content_format="text",
                content_text=exiftool_result.stdout,
                content_size=len(exiftool_result.stdout),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="exiftool"
            )
            db.session.add(content)

            # Parse exiftool output for interesting metadata
            interesting_metadata = {}
            for line in exiftool_result.stdout.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    interesting_metadata[key] = value

            # Create finding for interesting metadata
            if interesting_metadata:
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="metadata",
                    category="metadata_analysis",
                    title="ExifTool metadata analysis",
                    description=f"ExifTool found {len(interesting_metadata)} metadata fields.",
                    confidence_level=8,
                    priority=6,
                    severity="medium",
                    analysis_method="exiftool",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data={'metadata': interesting_metadata}
                )
                db.session.add(finding)

            db.session.commit()
    except Exception as e:
        logger.warning(f"ExifTool extraction failed or not available: {str(e)}")

    # Try steghide with empty password (works on some files)
    try:
        steghide_output = os.path.join(exotic_dir, "steghide_extracted")
        steghide_result = subprocess.run(['steghide', 'extract', '-sf', file_path, '-xf', steghide_output, '-p', ''], 
                      stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        logger.info(f"Steghide extraction successful: {steghide_output}")

        # Store steghide results in database if file record is provided
        if file_record and os.path.exists(steghide_output) and os.path.getsize(steghide_output) > 0:
            # Read extracted data
            with open(steghide_output, 'rb') as f:
                steghide_data = f.read()

            # Store steghide data as file content
            content = FileContent(
                file_id=file_record.id,
                content_type="steghide_extracted_data",
                content_format="binary",
                content_bytes=steghide_data,
                content_size=len(steghide_data),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="steghide"
            )
            db.session.add(content)

            # Create finding for steghide extraction
            finding = Finding(
                file_id=file_record.id,
                finding_type="steganography",
                category="steganography",
                title="Steghide hidden data found",
                description=f"Steghide extracted {len(steghide_data)} bytes of hidden data with empty password.",
                confidence_level=9,
                priority=8,
                severity="high",
                analysis_method="steghide",
                created_by=ADMIN_USER_ID,
                created_at=datetime.utcnow(),
                evidence_data={'data_size': len(steghide_data)}
            )
            db.session.add(finding)

            # Create file record for extracted data
            steghide_file_hash = hashlib.sha256(steghide_data).hexdigest()
            steghide_file_record = AnalysisFile.query.filter_by(sha256_hash=steghide_file_hash).first()

            if not steghide_file_record:
                # Save extracted data to file
                temp_dir = os.path.join('bulk_uploads/discovered_files')
                os.makedirs(temp_dir, exist_ok=True)
                temp_file = os.path.join(temp_dir, f"{os.path.basename(file_path)}_steghide_extracted")
                with open(temp_file, 'wb') as f:
                    f.write(steghide_data)

                # Identify file type
                steghide_file_type = identify_file_type(steghide_output)

                steghide_file_record = AnalysisFile(
                    filename=f"{os.path.basename(file_path)}_steghide_extracted",
                    filepath=temp_file,
                    file_size=len(steghide_data),
                    file_type=steghide_file_type,
                    mime_type=steghide_file_type,
                    sha256_hash=steghide_file_hash,
                    status=FileStatus.PROCESSING,
                    is_root_file=False,
                    parent_file_sha=file_record.sha256_hash,
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow()
                )
                db.session.add(steghide_file_record)
                db.session.flush()  # Get the ID

            # Create relationship
            relationship = ExtractionRelationship(
                source_file_id=file_record.id,
                source_file_sha=file_record.sha256_hash,
                extracted_file_id=steghide_file_record.id,
                extracted_file_sha=steghide_file_record.sha256_hash,
                extraction_method="steghide",
                extraction_tool_version="1.0",
                extraction_command="steghide extract -sf " + file_path + " -xf " + steghide_output + " -p ''",
                confidence_score=0.9,
                extra_data={}
            )
            db.session.add(relationship)

            # Cache the extracted file record
            DB_FILE_RECORDS[steghide_file_hash] = steghide_file_record

            db.session.commit()
    except Exception as e:
        logger.warning(f"Steghide extraction failed or not available: {str(e)}")

    # Try stegdetect
    try:
        stegdetect_result = subprocess.run(['stegdetect', file_path], capture_output=True, text=True)
        with open(os.path.join(exotic_dir, "stegdetect_output.txt"), 'w') as f:
            f.write(stegdetect_result.stdout)
        logger.info(f"Stegdetect analysis complete")

        # Store stegdetect results in database if file record is provided
        if file_record:
            # Store stegdetect output as file content
            content = FileContent(
                file_id=file_record.id,
                content_type="stegdetect_output",
                content_format="text",
                content_text=stegdetect_result.stdout,
                content_size=len(stegdetect_result.stdout),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="stegdetect"
            )
            db.session.add(content)

            # Create finding if stegdetect found something
            if stegdetect_result.stdout and "negative" not in stegdetect_result.stdout.lower():
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="steganography",
                    category="steganography",
                    title="Stegdetect found steganography",
                    description=f"Stegdetect found potential steganography: {stegdetect_result.stdout}",
                    confidence_level=8,
                    priority=7,
                    severity="medium",
                    analysis_method="stegdetect",
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data={'output': stegdetect_result.stdout}
                )
                db.session.add(finding)

            db.session.commit()
    except Exception as e:
        logger.warning(f"Stegdetect analysis failed or not available: {str(e)}")

def extract_with_tool(file_path: str, output_dir: str, tool_name: str, file_record: AnalysisFile = None, params: Dict = None) -> None:
    """Extract data using a specific tool from the extractors"""
    logger.info(f"Extracting with {tool_name}: {file_path}")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    try:
        # Get extractor
        extractor = get_extractor(tool_name)
        if not extractor:
            logger.warning(f"Extractor {tool_name} not found")
            return

        # Run extraction with parameters if provided
        result = extractor.extract(file_path, params or {})

        # Save results to filesystem
        with open(os.path.join(output_dir, f"{tool_name}_results.txt"), 'w') as f:
            f.write(f"Success: {result['success']}\n")
            f.write(f"Details: {result['details']}\n")
            f.write(f"Confidence: {result['confidence']}\n")
            f.write(f"Command: {result.get('command_line', 'N/A')}\n\n")

            if 'metadata' in result:
                f.write("Metadata:\n")
                f.write(str(result['metadata']))

        # If extraction was successful and data was found
        if result['success'] and result['data']:
            # Save extracted data to filesystem
            output_file = os.path.join(output_dir, f"{tool_name}_extracted_data")
            with open(output_file, 'wb') as f:
                f.write(result['data'])
            logger.info(f"{tool_name} extracted {len(result['data'])} bytes to {output_file}")

            # Store results in database if file record is provided
            if file_record:
                # Store extraction results as file content
                content = FileContent(
                    file_id=file_record.id,
                    content_type=f"{tool_name}_results",
                    content_format="json",
                    content_json={
                        'success': result['success'],
                        'details': result['details'],
                        'confidence': result['confidence'],
                        'command_line': result.get('command_line', 'N/A'),
                        'metadata': result.get('metadata', {})
                    },
                    content_size=len(str(result)),
                    extracted_at=datetime.utcnow(),
                    extracted_by=ADMIN_USER_ID,
                    extraction_method=tool_name
                )
                db.session.add(content)

                # Store extracted data as file content
                data_content = FileContent(
                    file_id=file_record.id,
                    content_type=f"{tool_name}_extracted_data",
                    content_format="binary",
                    content_bytes=result['data'],
                    content_size=len(result['data']),
                    extracted_at=datetime.utcnow(),
                    extracted_by=ADMIN_USER_ID,
                    extraction_method=tool_name
                )
                db.session.add(data_content)

                # Create finding for successful extraction
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="steganography",
                    category="steganography",
                    title=f"Hidden data found with {tool_name}",
                    description=f"Found hidden data using {tool_name}. {result['details']}",
                    confidence_level=int(result['confidence'] * 10) if result['confidence'] < 1 else int(result['confidence']),
                    priority=8,
                    severity="high",
                    analysis_method=tool_name,
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data=result.get('metadata', {})
                )
                db.session.add(finding)

                # Create file record for extracted data
                extracted_data_hash = hashlib.sha256(result['data']).hexdigest()
                extracted_file_record = AnalysisFile.query.filter_by(sha256_hash=extracted_data_hash).first()

                if not extracted_file_record:
                    # Save extracted data to file
                    temp_dir = os.path.join('bulk_uploads/discovered_files')
                    os.makedirs(temp_dir, exist_ok=True)
                    temp_file = os.path.join(temp_dir, f"{os.path.basename(file_path)}_{tool_name}_extracted")
                    with open(temp_file, 'wb') as f:
                        f.write(result['data'])

                    # Try to identify file type
                    extracted_file_type = identify_file_type(output_file)

                    extracted_file_record = AnalysisFile(
                        filename=f"{os.path.basename(file_path)}_{tool_name}_extracted",
                        filepath=temp_file,
                        file_size=len(result['data']),
                        file_type=extracted_file_type,
                        mime_type=extracted_file_type,
                        sha256_hash=extracted_data_hash,
                        status=FileStatus.PROCESSING,
                        is_root_file=False,
                        parent_file_sha=file_record.sha256_hash,
                        created_by=ADMIN_USER_ID,
                        created_at=datetime.utcnow()
                    )
                    db.session.add(extracted_file_record)
                    db.session.flush()  # Get the ID

                # Create relationship
                relationship = ExtractionRelationship(
                    source_file_id=file_record.id,
                    source_file_sha=file_record.sha256_hash,
                    extracted_file_id=extracted_file_record.id,
                    extracted_file_sha=extracted_file_record.sha256_hash,
                    extraction_method=tool_name,
                    extraction_tool_version="1.0",
                    extraction_command=result.get('command_line', tool_name),
                    confidence_score=result['confidence'],
                    extra_data={}
                )
                db.session.add(relationship)

                # Cache the extracted file record
                DB_FILE_RECORDS[extracted_data_hash] = extracted_file_record

                db.session.commit()

            # Store results in database if file record is provided
            if file_record:
                # Store extraction results as file content
                content = FileContent(
                    file_id=file_record.id,
                    content_type=f"{tool_name}_results",
                    content_format="json",
                    content_json={
                        'success': result['success'],
                        'details': result['details'],
                        'confidence': result['confidence'],
                        'metadata': result.get('metadata', {})
                    },
                    content_size=len(str(result)),
                    extracted_at=datetime.utcnow(),
                    extracted_by=ADMIN_USER_ID,
                    extraction_method=tool_name
                )
                db.session.add(content)

                # Store extracted data as file content
                extracted_data_content = FileContent(
                    file_id=file_record.id,
                    content_type=f"{tool_name}_extracted_data",
                    content_format="binary",
                    content_bytes=result['data'],
                    content_size=len(result['data']),
                    extracted_at=datetime.utcnow(),
                    extracted_by=ADMIN_USER_ID,
                    extraction_method=tool_name
                )
                db.session.add(extracted_data_content)

                # Create finding if confidence is high enough
                if result['confidence'] > 0.5:
                    finding = Finding(
                        file_id=file_record.id,
                        finding_type="steganography",
                        category="steganography",
                        title=f"Hidden data found with {tool_name}",
                        description=f"Found hidden data using {tool_name}. {result['details']}",
                        confidence_level=int(result['confidence'] * 10),
                        priority=8,
                        severity="high",
                        analysis_method=tool_name,
                        created_by=ADMIN_USER_ID,
                        created_at=datetime.utcnow(),
                        evidence_data=result.get('metadata', {})
                    )
                    db.session.add(finding)

                # Use ExtractionEngine to create a new file for the extracted data
                try:
                    # Create a temporary file for the extracted data
                    temp_dir = os.path.join('bulk_uploads/discovered_files')
                    os.makedirs(temp_dir, exist_ok=True)
                    temp_file = os.path.join(temp_dir, f"{os.path.basename(file_path)}_{tool_name}_extracted")
                    with open(temp_file, 'wb') as f:
                        f.write(result['data'])

                    # Create a new file record for the extracted data
                    extracted_file_hash = calculate_file_hash(temp_file)
                    extracted_file = AnalysisFile.query.filter_by(sha256_hash=extracted_file_hash).first()

                    if not extracted_file:
                        extracted_file = AnalysisFile(
                            filename=f"{os.path.basename(file_path)}_{tool_name}_extracted",
                            filepath=temp_file,
                            file_size=len(result['data']),
                            file_type="application/octet-stream",
                            mime_type="application/octet-stream",
                            sha256_hash=extracted_file_hash,
                            status=FileStatus.PROCESSING,
                            is_root_file=False,
                            parent_file_sha=file_record.sha256_hash,
                            created_by=ADMIN_USER_ID,
                            created_at=datetime.utcnow()
                        )
                        db.session.add(extracted_file)
                        db.session.flush()  # Get the ID

                    # Create relationship
                    relationship = ExtractionRelationship(
                        source_file_id=file_record.id,
                        source_file_sha=file_record.sha256_hash,
                        extracted_file_id=extracted_file.id,
                        extracted_file_sha=extracted_file.sha256_hash,
                        extraction_method=tool_name,
                        extraction_tool_version="1.0",
                        extraction_command=result.get('command_line', ''),
                        confidence_score=result['confidence'],
                        extra_data=result.get('metadata', {})
                    )
                    db.session.add(relationship)

                    # Cache the extracted file record
                    DB_FILE_RECORDS[extracted_file_hash] = extracted_file
                except Exception as e:
                    logger.error(f"Error creating file record for extracted data: {str(e)}")

                db.session.commit()
    except Exception as e:
        logger.error(f"Error extracting with {tool_name}: {str(e)}")

def process_extracted_files(directory: str, depth: int) -> None:
    """Process all files in a directory recursively"""
    logger.info(f"Processing extracted files in {directory} at depth {depth}")

    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)

            # Skip very small files and known non-data files
            if os.path.getsize(file_path) < 10:
                continue

            if file.endswith('.txt') or file.endswith('.json') or file.endswith('.log'):
                # For text files, just check for encoded data
                extract_from_text(file_path, os.path.join(root, f"{file}_analysis"), depth)
                continue

            # Check if the file is an image
            file_type = identify_file_type(file_path)
            if "image/" in file_type:
                logger.info(f"Found image file during extraction: {file_path}")
                # For image files, run the full suite of steganography and file carving tools
                process_image_file(file_path, os.path.join(root, f"{file}_analysis"), depth)
                continue

            # Process the file
            process_file(file_path, os.path.join(root, f"{file}_analysis"), depth)

def process_image_file(file_path: str, output_dir: str, depth: int) -> None:
    """
    Process an image file with the full suite of steganography and file carving tools

    Args:
        file_path: Path to the image file
        output_dir: Directory to save extracted files
        depth: Current recursion depth
    """
    logger.info(f"Processing image file with full suite of tools: {file_path}")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Identify the image type
    file_type = identify_file_type(file_path)
    logger.info(f"Image type: {file_type}")

    # Run appropriate extractors based on image type
    if "image/png" in file_type:
        extract_from_png(file_path, output_dir, depth)
    elif "image/jpeg" in file_type or "image/jpg" in file_type:
        extract_from_jpeg(file_path, output_dir, depth)
    else:
        # For other image types, try both PNG and JPEG extractors
        logger.info(f"Unknown image type, trying all extractors")
        extract_from_png(file_path, output_dir, depth)
        extract_from_jpeg(file_path, output_dir, depth)

    # Always run binwalk for thorough extraction
    extract_with_binwalk(file_path, output_dir, depth)

    # Always run strings analysis
    extract_strings(file_path, output_dir, depth)

    # Run file command on the file
    run_file_command(file_path, output_dir)

    # Try exotic extraction methods
    try_exotic_extractions(file_path, output_dir, depth)

    # Process any files that were extracted
    process_extracted_files(output_dir, depth + 1)

def print_summary():
    """Print summary of extraction results"""
    print("\n=== EXTRACTION SUMMARY ===")
    print(f"Total files processed: {len(PROCESSED_FILES)}")

    # Count extracted files by type
    file_types = {}
    for root, dirs, files in os.walk(OUTPUT_DIR):
        for file in files:
            if file.endswith('.txt') or file.endswith('.json') or file.endswith('.log'):
                continue

            file_path = os.path.join(root, file)
            file_type = identify_file_type(file_path)

            if file_type in file_types:
                file_types[file_type] += 1
            else:
                file_types[file_type] = 1

    print("\nExtracted file types:")
    for file_type, count in file_types.items():
        print(f"  - {file_type}: {count} files")

    print("\nExtraction complete! All extracted files are in the 'extracted_files' directory.")

if __name__ == "__main__":
    main()
