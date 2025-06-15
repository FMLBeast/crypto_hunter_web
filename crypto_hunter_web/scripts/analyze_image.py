"""
Comprehensive steganography and file carving script for image.png
This script performs the most elaborate steganography and file carving effort
on the image.png file and documents everything in the database.
"""

import os
import sys
import logging
import time
from datetime import datetime
from typing import Dict, Any, List

# Add parent directory to path to allow imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import Flask app and db
from crypto_hunter_web import create_app
from crypto_hunter_web.extensions import db
from crypto_hunter_web.models import (
    AnalysisFile, FileContent, Finding, ExtractionRelationship,
    FileNode, GraphEdge, RegionOfInterest, FileStatus
)
from crypto_hunter_web.services.extractors import (
    analyze_png_file, extract_png_metadata, get_extractor,
    get_recommended_extractors
)
from crypto_hunter_web.services.extraction_engine import ExtractionEngine

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
IMAGE_PATH = "uploads/image.png"
ADMIN_USER_ID = 1  # Admin user ID for attribution

def main():
    """Main function to orchestrate the analysis"""
    logger.info("Starting comprehensive steganography and file carving analysis")

    # Verify the image exists
    if not os.path.exists(IMAGE_PATH):
        logger.error(f"Image file not found at {IMAGE_PATH}")
        return

    # Get or create the file record in the database
    file_record = get_or_create_file_record(IMAGE_PATH)

    # Step 1: Analyze PNG structure
    logger.info("Step 1: Analyzing PNG structure")
    analyze_png_structure(file_record)

    # Step 2: Extract metadata
    logger.info("Step 2: Extracting PNG metadata")
    extract_metadata(file_record)

    # Step 3: Run steganography extractors
    logger.info("Step 3: Running steganography extractors")
    run_steganography_extractors(file_record)

    # Step 4: Run file carving tools
    logger.info("Step 4: Running file carving tools")
    run_file_carving_tools(file_record)

    # Step 5: Run string analysis
    logger.info("Step 5: Running string analysis")
    run_string_analysis(file_record)

    # Step 6: Create graph visualization
    logger.info("Step 6: Creating graph visualization")
    create_graph_visualization(file_record)

    # Mark file as analyzed
    file_record.status = FileStatus.COMPLETE
    file_record.analyzed_at = datetime.utcnow()
    file_record.analyzed_by = ADMIN_USER_ID
    db.session.commit()

    logger.info("Analysis complete!")

def get_or_create_file_record(file_path: str) -> AnalysisFile:
    """Get or create a file record in the database"""
    file_size = os.path.getsize(file_path)
    filename = os.path.basename(file_path)

    # Calculate SHA256 hash
    import hashlib
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    sha256 = sha256_hash.hexdigest()

    # Check if file already exists in database
    file_record = AnalysisFile.query.filter_by(sha256_hash=sha256).first()

    if not file_record:
        # Create new file record
        file_record = AnalysisFile(
            filename=filename,
            filepath=file_path,
            file_size=file_size,
            file_type="image/png",
            mime_type="image/png",
            sha256_hash=sha256,
            status=FileStatus.PROCESSING,
            is_root_file=True,
            created_by=ADMIN_USER_ID,
            created_at=datetime.utcnow()
        )
        db.session.add(file_record)
        db.session.commit()
        logger.info(f"Created new file record for {filename} with ID {file_record.id}")
    else:
        logger.info(f"Found existing file record for {filename} with ID {file_record.id}")
        # Update status to processing
        file_record.status = FileStatus.PROCESSING
        db.session.commit()

    return file_record

def analyze_png_structure(file_record: AnalysisFile):
    """Analyze PNG structure and store results"""
    try:
        # Analyze PNG file
        analysis_results = analyze_png_file(file_record.filepath)

        if 'error' in analysis_results:
            logger.error(f"PNG analysis error: {analysis_results['error']}")
            return

        # Store analysis results
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

        # Create finding for text data if present
        if analysis_results.get('has_text_data', False):
            finding = Finding(
                file_id=file_record.id,
                finding_type="text_data",
                category="steganography",
                title="Text data found in PNG",
                description="The PNG file contains text chunks (tEXt, zTXt, or iTXt) which may contain hidden messages or metadata.",
                confidence_level=8,
                priority=7,
                severity="medium",
                analysis_method="png_analyzer",
                created_by=ADMIN_USER_ID,
                created_at=datetime.utcnow()
            )
            db.session.add(finding)

        db.session.commit()
        logger.info("PNG structure analysis complete")

    except Exception as e:
        logger.error(f"Error analyzing PNG structure: {str(e)}")
        db.session.rollback()

def extract_metadata(file_record: AnalysisFile):
    """Extract PNG metadata and store results"""
    try:
        # Extract metadata
        metadata_results = extract_png_metadata(file_record.filepath)

        if 'error' in metadata_results:
            logger.error(f"PNG metadata extraction error: {metadata_results['error']}")
            return

        # Store metadata results
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
        logger.info("PNG metadata extraction complete")

    except Exception as e:
        logger.error(f"Error extracting PNG metadata: {str(e)}")
        db.session.rollback()

def run_steganography_extractors(file_record: AnalysisFile):
    """Run steganography extractors on the image"""
    # Get recommended extractors for PNG
    extractors = ['zsteg', 'zsteg_bitplane_1', 'zsteg_bitplane_2', 'zsteg_bitplane_3', 'zsteg_bitplane_4', 'steghide']

    for extractor_name in extractors:
        try:
            logger.info(f"Running {extractor_name} extractor")

            # Get extractor
            extractor = get_extractor(extractor_name)
            if not extractor:
                logger.warning(f"Extractor {extractor_name} not found")
                continue

            # Run extraction
            result = extractor.extract(file_record.filepath, {})

            # Store results
            content = FileContent(
                file_id=file_record.id,
                content_type=f"{extractor_name}_results",
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
                extraction_method=extractor_name
            )
            db.session.add(content)

            # If extraction was successful and data was found
            if result['success'] and result['data']:
                # Store extracted data
                extracted_data_content = FileContent(
                    file_id=file_record.id,
                    content_type=f"{extractor_name}_extracted_data",
                    content_format="binary",
                    content_bytes=result['data'],
                    content_size=len(result['data']),
                    extracted_at=datetime.utcnow(),
                    extracted_by=ADMIN_USER_ID,
                    extraction_method=extractor_name
                )
                db.session.add(extracted_data_content)

                # Create finding
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="steganography",
                    category="steganography",
                    title=f"Hidden data found with {extractor_name}",
                    description=f"Found hidden data using {extractor_name}. {result['details']}",
                    confidence_level=int(result['confidence'] * 10),
                    priority=8,
                    severity="high",
                    analysis_method=extractor_name,
                    created_by=ADMIN_USER_ID,
                    created_at=datetime.utcnow(),
                    evidence_data=result.get('metadata', {})
                )
                db.session.add(finding)

                # Use ExtractionEngine to create a new file for the extracted data
                ExtractionEngine.extract_from_file(file_record, extractor_name, {}, ADMIN_USER_ID)

            db.session.commit()
            logger.info(f"{extractor_name} extraction complete")

        except Exception as e:
            logger.error(f"Error running {extractor_name}: {str(e)}")
            db.session.rollback()

def run_file_carving_tools(file_record: AnalysisFile):
    """Run file carving tools on the image"""
    # Use binwalk and foremost
    carving_tools = ['binwalk', 'foremost']

    for tool_name in carving_tools:
        try:
            logger.info(f"Running {tool_name} extractor")

            # Get extractor
            extractor = get_extractor(tool_name)
            if not extractor:
                logger.warning(f"Extractor {tool_name} not found")
                continue

            # Run extraction
            result = extractor.extract(file_record.filepath, {})

            # Store results
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

            # If extraction was successful and data was found
            if result['success'] and result['data']:
                # Store extracted data
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

                # Create finding
                finding = Finding(
                    file_id=file_record.id,
                    finding_type="file_carving",
                    category="file_carving",
                    title=f"Embedded files found with {tool_name}",
                    description=f"Found embedded files using {tool_name}. {result['details']}",
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
                ExtractionEngine.extract_from_file(file_record, tool_name, {}, ADMIN_USER_ID)

            db.session.commit()
            logger.info(f"{tool_name} extraction complete")

        except Exception as e:
            logger.error(f"Error running {tool_name}: {str(e)}")
            db.session.rollback()

def run_string_analysis(file_record: AnalysisFile):
    """Run string analysis on the image"""
    try:
        logger.info("Running strings extractor")

        # Get extractor
        extractor = get_extractor('strings')
        if not extractor:
            logger.warning("Strings extractor not found")
            return

        # Run extraction
        result = extractor.extract(file_record.filepath, {'min_length': 4})

        # Store results
        content = FileContent(
            file_id=file_record.id,
            content_type="strings_results",
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
            extraction_method="strings"
        )
        db.session.add(content)

        # Store extracted strings
        if result['success'] and result['data']:
            strings_content = FileContent(
                file_id=file_record.id,
                content_type="strings_output",
                content_format="text",
                content_text=result['data'].decode('utf-8', errors='ignore'),
                content_size=len(result['data']),
                extracted_at=datetime.utcnow(),
                extracted_by=ADMIN_USER_ID,
                extraction_method="strings"
            )
            db.session.add(strings_content)

            # Create findings for interesting strings
            if 'metadata' in result and 'analysis' in result['metadata']:
                analysis = result['metadata']['analysis']

                for interesting_string in analysis.get('interesting_strings', []):
                    finding = Finding(
                        file_id=file_record.id,
                        finding_type="interesting_string",
                        category="string_analysis",
                        title=f"Interesting string: {interesting_string['type']}",
                        description=f"Found interesting string: {interesting_string['string']}",
                        confidence_level=6,
                        priority=5,
                        severity="medium",
                        analysis_method="strings",
                        created_by=ADMIN_USER_ID,
                        created_at=datetime.utcnow(),
                        evidence_data=interesting_string
                    )
                    db.session.add(finding)

        db.session.commit()
        logger.info("String analysis complete")

    except Exception as e:
        logger.error(f"Error running string analysis: {str(e)}")
        db.session.rollback()

def create_graph_visualization(file_record: AnalysisFile):
    """Create graph visualization for the file and its extracted content"""
    try:
        # Create node for the main file
        main_node = FileNode(
            file_id=file_record.id,
            file_sha=file_record.sha256_hash,
            node_type="root",
            graph_level=0,
            node_color="#3b82f6",  # Blue
            node_size=20,
            node_shape="circle",
            extra_data={
                'label': file_record.filename,
                'file_type': file_record.file_type
            }
        )
        db.session.add(main_node)
        db.session.flush()  # Get the ID

        # Create nodes for extracted files
        child_files = AnalysisFile.query.filter_by(parent_file_sha=file_record.sha256_hash).all()

        for idx, child_file in enumerate(child_files):
            # Create node for child file
            child_node = FileNode(
                file_id=child_file.id,
                file_sha=child_file.sha256_hash,
                node_type="extracted",
                graph_level=1,
                position_x=100 + (idx * 50),
                position_y=100,
                node_color="#ef4444",  # Red
                node_size=15,
                node_shape="circle",
                extra_data={
                    'label': child_file.filename,
                    'file_type': child_file.file_type
                }
            )
            db.session.add(child_node)
            db.session.flush()  # Get the ID

            # Create edge between main file and child file
            edge = GraphEdge(
                source_node_id=main_node.id,
                target_node_id=child_node.id,
                edge_type="extracted_from",
                weight=1.0,
                edge_color="#6b7280",  # Gray
                edge_width=2,
                edge_style="solid",
                extra_data={
                    'label': child_file.extraction_method if hasattr(child_file, 'extraction_method') else "extracted"
                }
            )
            db.session.add(edge)

        db.session.commit()
        logger.info("Graph visualization created")

    except Exception as e:
        logger.error(f"Error creating graph visualization: {str(e)}")
        db.session.rollback()

if __name__ == "__main__":
    # Create Flask app with SQLite database for testing
    import os
    os.environ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
    os.environ['DATABASE_URL'] = 'sqlite:///test.db'

    # Create Flask app and application context
    app = create_app()
    with app.app_context():
        # Create database tables
        db.create_all()

        # Run the main function
        main()
